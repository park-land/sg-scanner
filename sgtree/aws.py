"""boto3 data-fetching helpers.

Everything here is read-only (Describe*/List*/Get*) and scoped to a single
region, since a security group reference (ReferencedGroupInfo) is only ever
valid within the same region (same VPC or a same-region VPC peering
connection). Cross-region and cross-account references cannot be resolved
and are reported as external leaves instead of traversed.
"""
import re

import boto3

_SG_PATTERN = re.compile(r'sg-[0-9a-f]{8,17}')


def get_vpc_cidr_blocks(session, region):
    """Every CIDR block (primary + secondary IPv4, plus any IPv6) owned by a
    VPC in this region, for classifying a rule's CIDR as internal/external."""
    import ipaddress
    ec2 = session.client('ec2', region_name=region)
    blocks = []
    for page in ec2.get_paginator('describe_vpcs').paginate():
        for vpc in page['Vpcs']:
            name = next((t['Value'] for t in vpc.get('Tags', []) if t['Key'] == 'Name'), None)
            for assoc in vpc.get('CidrBlockAssociationSet', []):
                cidr = assoc.get('CidrBlock')
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                blocks.append({'vpc_id': vpc['VpcId'], 'name': name, 'cidr': str(net), 'network': net})
            for assoc in vpc.get('Ipv6CidrBlockAssociationSet', []):
                cidr = assoc.get('Ipv6CidrBlock')
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                blocks.append({'vpc_id': vpc['VpcId'], 'name': name, 'cidr': str(net), 'network': net})
    return blocks


def get_subnet_cidr_blocks(session, region):
    """Every subnet CIDR (IPv4 and IPv6) in this region, for narrowing an
    internal match down from 'this VPC' to 'this subnet'."""
    import ipaddress
    ec2 = session.client('ec2', region_name=region)
    blocks = []
    for page in ec2.get_paginator('describe_subnets').paginate():
        for sn in page['Subnets']:
            name = next((t['Value'] for t in sn.get('Tags', []) if t['Key'] == 'Name'), None)
            cidr = sn.get('CidrBlock')
            if cidr:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    blocks.append({'subnet_id': sn['SubnetId'], 'vpc_id': sn['VpcId'],
                                    'az': sn.get('AvailabilityZone'), 'name': name,
                                    'cidr': str(net), 'network': net})
                except ValueError:
                    pass
            for assoc in sn.get('Ipv6CidrBlockAssociationSet', []):
                cidr6 = assoc.get('Ipv6CidrBlock')
                if not cidr6:
                    continue
                try:
                    net = ipaddress.ip_network(cidr6, strict=False)
                    blocks.append({'subnet_id': sn['SubnetId'], 'vpc_id': sn['VpcId'],
                                    'az': sn.get('AvailabilityZone'), 'name': name,
                                    'cidr': str(net), 'network': net})
                except ValueError:
                    pass
    return blocks


def get_account_public_ips(session, region, include_claude=False, claude_model=None):
    """Public IPs this account owns in this region — Elastic IPs, ENI
    auto-assigned public IPs, and NAT Gateway public IPs — used to tell
    whether an 'external' CIDR in a rule is actually one of our own
    resources (e.g. a rule scoped to our own NAT Gateway's IP).

    Each IP is traced to its actual owning resource via resolve_enis() —
    e.g. an Elastic IP on an ALB's ENI resolves to "Application Load Balancer
    'my-alb'", not just the ENI id — the same resolution used for the SG
    attachment scan.
    """
    ec2 = session.client('ec2', region_name=region)
    entries = []

    enis = []
    try:
        for page in ec2.get_paginator('describe_network_interfaces').paginate():
            enis.extend(page['NetworkInterfaces'])
    except Exception:
        pass
    resolved = resolve_enis(session, region, enis, include_claude=include_claude, claude_model=claude_model) if enis else {}

    seen_ips = set()

    # 1. Elastic IPs — resolved through whichever ENI they're associated
    #    with, so an EIP on a NAT Gateway/ALB/instance shows that resource.
    try:
        resp = ec2.describe_addresses()
        for addr in resp.get('Addresses', []):
            ip = addr.get('PublicIp')
            if not ip:
                continue
            eip_name = next((t['Value'] for t in addr.get('Tags', []) if t['Key'] == 'Name'), None)
            eni_id = addr.get('NetworkInterfaceId')
            r = resolved.get(eni_id) if eni_id else None
            if r:
                resource_type, resource_id, label, inferred = r['resource_type'], r['resource_id'], r['label'], r['inferred']
            elif addr.get('InstanceId'):
                resource_type, resource_id, label, inferred = 'instance', addr['InstanceId'], addr['InstanceId'], False
            elif eni_id:
                resource_type, resource_id, label, inferred = 'network_interface', eni_id, eni_id, False
            else:
                resource_type, resource_id = 'elastic_ip', addr.get('AllocationId', ip)
                label, inferred = f"Unassociated Elastic IP {resource_id}", False
            if eip_name and eip_name not in label:
                label = f'{label} — EIP "{eip_name}"'
            entries.append({'ip': ip, 'service': 'ec2', 'resource_type': resource_type,
                             'resource_id': resource_id, 'resource_name': label, 'inferred': inferred})
            seen_ips.add(ip)
    except Exception:
        pass

    # 2. ENI auto-assigned public IPs not already covered by an EIP above.
    for eni in enis:
        pub = eni.get('Association', {}).get('PublicIp')
        if not pub or pub in seen_ips:
            continue
        r = resolved.get(eni['NetworkInterfaceId'])
        if r:
            entries.append({'ip': pub, 'service': 'ec2', 'resource_type': r['resource_type'],
                             'resource_id': r['resource_id'], 'resource_name': r['label'], 'inferred': r['inferred']})
        else:
            entries.append({'ip': pub, 'service': 'ec2', 'resource_type': 'network_interface',
                             'resource_id': eni['NetworkInterfaceId'],
                             'resource_name': eni.get('Description') or eni['NetworkInterfaceId'], 'inferred': False})
        seen_ips.add(pub)

    # 3. NAT Gateway public IPs (kept as an explicit source — reliable and
    #    specific even when not separately visible as an EIP association).
    try:
        for page in ec2.get_paginator('describe_nat_gateways').paginate():
            for nat in page['NatGateways']:
                for addr in nat.get('NatGatewayAddresses', []):
                    pub = addr.get('PublicIp')
                    if pub and pub not in seen_ips:
                        entries.append({'ip': pub, 'service': 'ec2', 'resource_type': 'nat_gateway',
                                         'resource_id': nat['NatGatewayId'], 'resource_name': nat['NatGatewayId'],
                                         'inferred': False})
                        seen_ips.add(pub)
    except Exception:
        pass

    return entries


def get_prefix_list_names(session, region):
    """pl-id -> human name, for rules whose source is a managed prefix list
    rather than a CIDR or SG."""
    ec2 = session.client('ec2', region_name=region)
    names = {}
    try:
        for page in ec2.get_paginator('describe_managed_prefix_lists').paginate():
            for pl in page['PrefixLists']:
                names[pl['PrefixListId']] = pl.get('PrefixListName', pl['PrefixListId'])
    except Exception:
        pass
    return names


def get_session(profile=None):
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def get_account_id(session):
    return session.client('sts').get_caller_identity()['Account']


def get_enabled_regions(session):
    ec2 = session.client('ec2', region_name='us-east-1')
    resp = ec2.describe_regions(
        Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
    )
    return [r['RegionName'] for r in resp['Regions']]


def find_sg_region(session, sg_id, regions=None):
    """Locate which region a security group lives in by probing each region.

    The credentials' own default region (from profile/env/config) is tried
    first, since that's the common case and saves probing every other region
    for nothing. Falls back through the rest of the enabled regions in
    whatever order they were returned.

    Returns the region name, or None if the SG isn't found anywhere reachable.
    """
    ordered = list(regions or get_enabled_regions(session))
    default_region = session.region_name
    if default_region and default_region in ordered:
        ordered.remove(default_region)
        ordered.insert(0, default_region)

    for region in ordered:
        ec2 = session.client('ec2', region_name=region)
        try:
            resp = ec2.describe_security_groups(GroupIds=[sg_id])
            if resp['SecurityGroups']:
                return region
        except Exception:
            continue
    return None


def get_security_group(session, region, sg_id):
    """Fetch a single SG's details.

    Returns (sg_dict_or_None, status) where status is one of:
      'found'     - sg_dict is populated
      'not_found' - the SG genuinely does not exist (safe to flag as stale)
      'error'     - couldn't tell (permissions, throttling, etc.) - sg_dict is
                    None but this must NOT be treated as proof of staleness
    """
    ec2 = session.client('ec2', region_name=region)
    try:
        resp = ec2.describe_security_groups(GroupIds=[sg_id])
    except ec2.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        if code in ('InvalidGroup.NotFound', 'InvalidGroupId.Malformed'):
            return None, 'not_found'
        return None, 'error'
    except Exception:
        return None, 'error'
    sgs = resp['SecurityGroups']
    if not sgs:
        return None, 'not_found'
    return sgs[0], 'found'


def get_security_group_rules(session, region, sg_id):
    ec2 = session.client('ec2', region_name=region)
    rules = []
    pag = ec2.get_paginator('describe_security_group_rules')
    for page in pag.paginate(Filters=[{'Name': 'group-id', 'Values': [sg_id]}]):
        rules.extend(page['SecurityGroupRules'])
    return rules


def get_all_security_group_ids(session, region):
    """All SG ids that exist in this region, used to validate cross-references
    that fall outside the tree we've traversed."""
    ec2 = session.client('ec2', region_name=region)
    ids = set()
    pag = ec2.get_paginator('describe_security_groups')
    for page in pag.paginate():
        for sg in page['SecurityGroups']:
            ids.add(sg['GroupId'])
    return ids


def _add(attach_map, sg_id, service, resource_type, resource_id, resource_name=None, inferred=False):
    if not sg_id:
        return
    attach_map.setdefault(sg_id, []).append({
        'service':       service,
        'resource_type': resource_type,
        'resource_id':   resource_id,
        'resource_name': resource_name or resource_id,
        'inferred':      inferred,   # True if a Claude guess rather than a deterministic lookup
    })


# AWS's managed services stamp identifying text into an ENI's InterfaceType
# and/or Description. These cover the documented conventions; anything that
# doesn't match falls back to Claude (see get_attachment_map).
_ENI_INTERFACE_TYPE_LABELS = {
    'nat_gateway':                     'NAT Gateway',
    'vpc_endpoint':                    'VPC Endpoint',
    'transit_gateway':                 'Transit Gateway attachment',
    'efa':                             'Elastic Fabric Adapter',
    'efs':                             'EFS mount target',
    'lambda':                          'Lambda-managed ENI',
    'gateway_load_balancer':           'Gateway Load Balancer',
    'gateway_load_balancer_endpoint':  'Gateway Load Balancer Endpoint',
    'network_load_balancer':           'Network Load Balancer',
    'load_balancer':                   'Classic Load Balancer',
    'quicksight':                      'QuickSight',
    'api_gateway_managed':             'API Gateway (VPC link)',
    'branch':                          'App Mesh / branch ENI',
    'trunk':                           'Trunk ENI',
}

_ENI_DESC_PATTERNS = [
    (re.compile(r'^ELB (net|app|gwy)/([^/]+)/'), lambda m: {
        'net': 'Network', 'app': 'Application', 'gwy': 'Gateway'
    }[m.group(1)] + f" Load Balancer '{m.group(2)}'"),
    (re.compile(r'^RDS Proxy'), lambda m: 'RDS Proxy'),
    (re.compile(r'^RDSNetworkInterface'), lambda m: 'RDS-managed network interface'),
    (re.compile(r'^AWS created network interface for directory (\S+)'), lambda m: f'Directory Service directory {m.group(1)}'),
    (re.compile(r'^Interface for NAT Gateway (nat-\w+)'), lambda m: f'NAT Gateway {m.group(1)}'),
    (re.compile(r'^VPC Endpoint Interface (vpce-\w+)'), lambda m: f'VPC Endpoint {m.group(1)}'),
    (re.compile(r'^ElastiCache '), lambda m: 'ElastiCache-managed network interface'),
    (re.compile(r'^EFS mount target'), lambda m: 'EFS mount target'),
    (re.compile(r'^AWS Lambda VPC ENI'), lambda m: 'Lambda-managed network interface'),
    (re.compile(r'^DAX '), lambda m: 'DynamoDB Accelerator (DAX) node'),
    (re.compile(r'^CloudHSM Management Interface'), lambda m: 'CloudHSM management interface'),
    (re.compile(r'^Network Interface for Transit Gateway Attachment (tgw-attach-\w+)'), lambda m: f'Transit Gateway attachment {m.group(1)}'),
    (re.compile(r'^Redshift '), lambda m: 'Redshift-managed network interface'),
    (re.compile(r'^AWS ParallelCluster'), lambda m: 'ParallelCluster-managed network interface'),
]


def _classify_eni_deterministic(eni):
    """Best-effort label from InterfaceType/Description patterns AWS documents
    for its managed services. Returns None if nothing matched — the caller
    decides whether to fall back to a direct EC2 instance lookup or Claude."""
    itype = eni.get('InterfaceType', '')
    if itype and itype != 'interface' and itype in _ENI_INTERFACE_TYPE_LABELS:
        base = _ENI_INTERFACE_TYPE_LABELS[itype]
        desc = eni.get('Description') or ''
        m = re.search(r'([a-z]+-[0-9a-f]{8,17})', desc)
        return f'{base} ({m.group(1)})' if m else base

    desc = eni.get('Description') or ''
    for pattern, fmt in _ENI_DESC_PATTERNS:
        m = pattern.match(desc)
        if m:
            return fmt(m)
    return None


def _resolve_instance_labels(session, region, instance_ids):
    """Batch-resolve EC2 instance ids to a 'i-xxx (Name tag)' label."""
    if not instance_ids:
        return {}
    ec2 = session.client('ec2', region_name=region)
    ids = list(instance_ids)
    labels = {}
    for i in range(0, len(ids), 200):
        try:
            for page in ec2.get_paginator('describe_instances').paginate(InstanceIds=ids[i:i + 200]):
                for res in page['Reservations']:
                    for inst in res['Instances']:
                        name = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), None)
                        labels[inst['InstanceId']] = f"{inst['InstanceId']} ({name})" if name else inst['InstanceId']
        except Exception:
            pass
    return labels


def resolve_enis(session, region, enis, include_claude=False, claude_model=None):
    """Resolve each given ENI (as returned by describe_network_interfaces) to
    its owning resource, not just the ENI id — used both for the SG
    attachment scan and for tracing an account-owned public IP back to its
    real resource. Returns {eni_id: {'resource_type', 'resource_id', 'label',
    'inferred'}}.

    Resolution order: a direct EC2 instance attachment (batch-resolved to its
    Name tag) beats everything else; then the deterministic InterfaceType/
    Description patterns AWS documents for its managed services; anything
    still unresolved falls back to a raw description, upgraded to a Claude
    best-guess (batched into one call) when include_claude is set.
    """
    results = {}
    pending_instance = []  # (eni_id, instance_id)
    unresolved = []        # eni dicts

    for eni in enis:
        eni_id = eni['NetworkInterfaceId']
        instance_id = eni.get('Attachment', {}).get('InstanceId')
        if instance_id:
            pending_instance.append((eni_id, instance_id))
            continue
        label = _classify_eni_deterministic(eni)
        if label:
            results[eni_id] = {'resource_type': 'network_interface', 'resource_id': eni_id,
                                'label': label, 'inferred': False}
        else:
            unresolved.append(eni)
            results[eni_id] = {'resource_type': 'network_interface', 'resource_id': eni_id,
                                'label': eni.get('Description') or eni_id, 'inferred': False}

    instance_labels = _resolve_instance_labels(session, region, {iid for _, iid in pending_instance})
    for eni_id, instance_id in pending_instance:
        results[eni_id] = {'resource_type': 'instance', 'resource_id': instance_id,
                            'label': instance_labels.get(instance_id, instance_id), 'inferred': False}

    if unresolved and include_claude:
        from . import claude_helper
        model = claude_model or claude_helper.DEFAULT_MODEL
        guesses = claude_helper.classify_enis(
            [{'eni_id': e['NetworkInterfaceId'], 'description': e.get('Description') or '',
              'interface_type': e.get('InterfaceType') or '', 'requester_id': e.get('RequesterId') or ''}
             for e in unresolved],
            model=model,
        )
        for eni in unresolved:
            eni_id = eni['NetworkInterfaceId']
            if eni_id in guesses:
                results[eni_id]['label'] = guesses[eni_id]
                results[eni_id]['inferred'] = True

    return results


def get_attachment_map(session, region, errors=None, include_claude=False, claude_model=None):
    """Map of SG id -> list of specific resources referencing it, across the
    same ~21 service surfaces the account-wide scanner checks. Unlike a plain
    used/unused set, each entry names the actual resource so a single SG's
    report can say *what* it's wired into.

    ENIs are a special case: their Description is often just a sub-resource
    label, so each one is resolved via resolve_enis() to its owning resource
    instead of being left as a bare ENI id.
    """
    attach_map = {}

    # 1. Network interfaces (EC2, RDS, ELB, etc.) — resolved to their owning
    #    resource rather than left as a bare ENI id.
    try:
        ec2 = session.client('ec2', region_name=region)
        enis = []
        for page in ec2.get_paginator('describe_network_interfaces').paginate():
            enis.extend(page['NetworkInterfaces'])
        resolved = resolve_enis(session, region, enis, include_claude=include_claude, claude_model=claude_model)
        for eni in enis:
            group_ids = [g['GroupId'] for g in eni.get('Groups', [])]
            if not group_ids:
                continue
            r = resolved.get(eni['NetworkInterfaceId'])
            if not r:
                continue
            for gid in group_ids:
                _add(attach_map, gid, 'ec2', r['resource_type'], r['resource_id'], r['label'], inferred=r['inferred'])
    except Exception:
        pass

    # 2. EC2 Launch Templates
    try:
        ec2 = session.client('ec2', region_name=region)
        for page in ec2.get_paginator('describe_launch_templates').paginate():
            for lt in page['LaunchTemplates']:
                try:
                    ver = ec2.describe_launch_template_versions(
                        LaunchTemplateId=lt['LaunchTemplateId'], Versions=['$Default']
                    )['LaunchTemplateVersions']
                    for v in ver:
                        data = v.get('LaunchTemplateData', {})
                        for ni in data.get('NetworkInterfaces', []):
                            for sg in ni.get('Groups', []):
                                _add(attach_map, sg, 'ec2', 'launch_template', lt['LaunchTemplateId'], lt.get('LaunchTemplateName'))
                        for sg in data.get('SecurityGroupIds', []):
                            _add(attach_map, sg, 'ec2', 'launch_template', lt['LaunchTemplateId'], lt.get('LaunchTemplateName'))
                        for sg in data.get('SecurityGroups', []):
                            _add(attach_map, sg, 'ec2', 'launch_template', lt['LaunchTemplateId'], lt.get('LaunchTemplateName'))
                except Exception:
                    pass
    except Exception:
        pass

    # 2b. EC2 Launch Configurations (legacy Auto Scaling)
    try:
        asg = session.client('autoscaling', region_name=region)
        for page in asg.get_paginator('describe_launch_configurations').paginate():
            for lc in page['LaunchConfigurations']:
                for sg in lc.get('SecurityGroups', []):
                    _add(attach_map, sg, 'autoscaling', 'launch_configuration', lc['LaunchConfigurationName'])
    except Exception:
        pass

    # 3. Lambda VPC configurations
    try:
        lam = session.client('lambda', region_name=region)
        for page in lam.get_paginator('list_functions').paginate():
            for fn in page['Functions']:
                for sg in fn.get('VpcConfig', {}).get('SecurityGroupIds', []):
                    _add(attach_map, sg, 'lambda', 'function', fn['FunctionName'])
    except Exception:
        pass

    # 4. ECS Services (networkConfiguration)
    try:
        ecs = session.client('ecs', region_name=region)
        for page in ecs.get_paginator('list_clusters').paginate():
            for arn in page.get('clusterArns', []):
                try:
                    for svc_page in ecs.get_paginator('list_services').paginate(cluster=arn):
                        if svc_page.get('serviceArns'):
                            svcs = ecs.describe_services(cluster=arn, services=svc_page['serviceArns'])
                            for svc in svcs.get('services', []):
                                nc = svc.get('networkConfiguration', {}).get('awsvpcConfiguration', {})
                                for sg in nc.get('securityGroups', []):
                                    _add(attach_map, sg, 'ecs', 'service', svc['serviceName'])
                except Exception:
                    pass
    except Exception:
        pass

    # 5. CodeBuild projects with VPC config
    try:
        cb = session.client('codebuild', region_name=region)
        projects = []
        for page in cb.get_paginator('list_projects').paginate():
            projects.extend(page.get('projects', []))
        if projects:
            for i in range(0, len(projects), 100):
                batch = cb.batch_get_projects(names=projects[i:i + 100])
                for p in batch.get('projects', []):
                    for sg in p.get('vpcConfig', {}).get('securityGroupIds', []):
                        _add(attach_map, sg, 'codebuild', 'project', p['name'])
    except Exception:
        pass

    # 6. RDS / Aurora
    try:
        rds = session.client('rds', region_name=region)
        for page in rds.get_paginator('describe_db_instances').paginate():
            for db in page['DBInstances']:
                for sg in db.get('VpcSecurityGroups', []):
                    if sg.get('VpcSecurityGroupId'):
                        _add(attach_map, sg['VpcSecurityGroupId'], 'rds', 'db_instance', db['DBInstanceIdentifier'])
        for page in rds.get_paginator('describe_db_clusters').paginate():
            for cl in page['DBClusters']:
                for sg in cl.get('VpcSecurityGroups', []):
                    if sg.get('VpcSecurityGroupId'):
                        _add(attach_map, sg['VpcSecurityGroupId'], 'rds', 'db_cluster', cl['DBClusterIdentifier'])
    except Exception:
        pass

    # 7. ElastiCache clusters and serverless caches
    try:
        ec = session.client('elasticache', region_name=region)
        for page in ec.get_paginator('describe_cache_clusters').paginate():
            for cl in page['CacheClusters']:
                for sg in cl.get('SecurityGroups', []):
                    if sg.get('SecurityGroupId'):
                        _add(attach_map, sg['SecurityGroupId'], 'elasticache', 'cache_cluster', cl['CacheClusterId'])
        try:
            resp = ec.describe_serverless_caches()
            for sc in resp.get('ServerlessCaches', []):
                for sg in sc.get('SecurityGroupIds', []):
                    _add(attach_map, sg, 'elasticache', 'serverless_cache', sc['ServerlessCacheName'])
        except Exception:
            pass
    except Exception:
        pass

    # 8. Glue connections
    try:
        glue = session.client('glue', region_name=region)
        kwargs = {}
        while True:
            resp = glue.get_connections(**kwargs)
            for conn in resp.get('ConnectionList', []):
                pcr = conn.get('PhysicalConnectionRequirements') or {}
                for sg in pcr.get('SecurityGroupIdList', []):
                    _add(attach_map, sg, 'glue', 'connection', conn.get('Name'))
            next_token = resp.get('NextToken')
            if not next_token:
                break
            kwargs['NextToken'] = next_token
    except Exception as e:
        if errors is not None:
            errors.append({'region': region, 'source': 'glue', 'error': str(e)})

    # 9. SageMaker domains and notebook instances
    try:
        sm = session.client('sagemaker', region_name=region)
        try:
            for domain in sm.list_domains().get('Domains', []):
                d = sm.describe_domain(DomainId=domain['DomainId'])
                for sg in d.get('DefaultUserSettings', {}).get('SecurityGroups', []):
                    _add(attach_map, sg, 'sagemaker', 'domain', d.get('DomainName'))
                for sg in d.get('DefaultSpaceSettings', {}).get('SecurityGroups', []):
                    _add(attach_map, sg, 'sagemaker', 'domain', d.get('DomainName'))
        except Exception:
            pass
        try:
            for page in sm.get_paginator('list_notebook_instances').paginate():
                for nb in page['NotebookInstances']:
                    detail = sm.describe_notebook_instance(NotebookInstanceName=nb['NotebookInstanceName'])
                    for sg in detail.get('SecurityGroups', []):
                        _add(attach_map, sg, 'sagemaker', 'notebook_instance', nb['NotebookInstanceName'])
        except Exception:
            pass
    except Exception:
        pass

    # 10. AWS Batch compute environments
    try:
        batch = session.client('batch', region_name=region)
        for page in batch.get_paginator('describe_compute_environments').paginate():
            for ce in page['computeEnvironments']:
                for sg in ce.get('computeResources', {}).get('securityGroupIds', []):
                    _add(attach_map, sg, 'batch', 'compute_environment', ce['computeEnvironmentName'])
    except Exception:
        pass

    # 11. MSK clusters
    try:
        kafka = session.client('kafka', region_name=region)
        for page in kafka.get_paginator('list_clusters_v2').paginate():
            for cl in page.get('ClusterInfoList', []):
                prov = cl.get('Provisioned', {})
                for sg in prov.get('BrokerNodeGroupInfo', {}).get('SecurityGroups', []):
                    _add(attach_map, sg, 'kafka', 'cluster', cl.get('ClusterName'))
                svl = cl.get('Serverless', {})
                for vpc_cfg in svl.get('VpcConfigs', []):
                    for sg in vpc_cfg.get('SecurityGroupIds', []):
                        _add(attach_map, sg, 'kafka', 'cluster', cl.get('ClusterName'))
    except Exception:
        pass

    # 12. App Runner VPC connectors
    try:
        ar = session.client('apprunner', region_name=region)
        resp = ar.list_vpc_connectors()
        for vc in resp.get('VpcConnectors', []):
            for sg in vc.get('SecurityGroups', []):
                _add(attach_map, sg, 'apprunner', 'vpc_connector', vc.get('VpcConnectorName'))
    except Exception:
        pass

    # 13. Directory Service (Managed AD)
    try:
        ds = session.client('ds', region_name=region)
        for d in ds.describe_directories().get('DirectoryDescriptions', []):
            sg = d.get('VpcSettings', {}).get('SecurityGroupId')
            if sg:
                _add(attach_map, sg, 'ds', 'directory', d.get('Name'))
    except Exception:
        pass

    # 14. EKS clusters
    try:
        eks = session.client('eks', region_name=region)
        for name in eks.list_clusters().get('clusters', []):
            cl = eks.describe_cluster(name=name).get('cluster', {})
            vpc_cfg = cl.get('resourcesVpcConfig', {})
            for sg in vpc_cfg.get('securityGroupIds', []):
                _add(attach_map, sg, 'eks', 'cluster', name)
            cluster_sg = vpc_cfg.get('clusterSecurityGroupId')
            if cluster_sg:
                _add(attach_map, cluster_sg, 'eks', 'cluster', name)
    except Exception:
        pass

    # 15. Redshift clusters
    try:
        rs = session.client('redshift', region_name=region)
        for page in rs.get_paginator('describe_clusters').paginate():
            for cl in page['Clusters']:
                for sg in cl.get('VpcSecurityGroups', []):
                    if sg.get('VpcSecurityGroupId'):
                        _add(attach_map, sg['VpcSecurityGroupId'], 'redshift', 'cluster', cl['ClusterIdentifier'])
    except Exception:
        pass

    # 16. Step Functions — SG IDs embedded in state machine definition JSON
    try:
        sfn = session.client('stepfunctions', region_name=region)
        for page in sfn.get_paginator('list_state_machines').paginate():
            for sm_ in page['stateMachines']:
                try:
                    defn = sfn.describe_state_machine(stateMachineArn=sm_['stateMachineArn'])
                    for sg in _SG_PATTERN.findall(defn.get('definition', '')):
                        _add(attach_map, sg, 'stepfunctions', 'state_machine', sm_['name'])
                except Exception:
                    pass
    except Exception:
        pass

    # 17. CloudFormation stacks — SG IDs in parameter values and outputs
    try:
        cfn = session.client('cloudformation', region_name=region)
        for page in cfn.get_paginator('describe_stacks').paginate():
            for stack in page['Stacks']:
                for p in stack.get('Parameters', []):
                    for sg in _SG_PATTERN.findall(p.get('ParameterValue', '')):
                        _add(attach_map, sg, 'cloudformation', 'stack', stack['StackName'])
                for o in stack.get('Outputs', []):
                    for sg in _SG_PATTERN.findall(o.get('OutputValue', '')):
                        _add(attach_map, sg, 'cloudformation', 'stack', stack['StackName'])
    except Exception:
        pass

    # 18. SSM Parameter Store
    try:
        ssm = session.client('ssm', region_name=region)
        for page in ssm.get_paginator('describe_parameters').paginate():
            for param in page['Parameters']:
                if param.get('Type') == 'SecureString':
                    continue
                try:
                    val = ssm.get_parameter(Name=param['Name']).get('Parameter', {}).get('Value', '')
                    for sg in _SG_PATTERN.findall(val):
                        _add(attach_map, sg, 'ssm', 'parameter', param['Name'])
                except Exception:
                    pass
    except Exception:
        pass

    # 19. Service Catalog provisioned products
    try:
        sc = session.client('servicecatalog', region_name=region)
        page_token = None
        while True:
            kwargs = {'AccessLevelFilter': {'Key': 'Account', 'Value': 'self'}}
            if page_token:
                kwargs['PageToken'] = page_token
            resp = sc.search_provisioned_products(**kwargs)
            for pp in resp.get('ProvisionedProducts', []):
                try:
                    detail = sc.describe_provisioned_product(Id=pp['Id']).get('ProvisionedProductDetail', {})
                    rec_id = detail.get('LastRecordId')
                    if rec_id:
                        rec = sc.describe_record(Id=rec_id)
                        for p in rec.get('RecordOutputs', []):
                            for sg in _SG_PATTERN.findall(p.get('OutputValue', '')):
                                _add(attach_map, sg, 'servicecatalog', 'provisioned_product', pp.get('Name'))
                except Exception:
                    pass
            page_token = resp.get('NextPageToken')
            if not page_token:
                break
    except Exception:
        pass

    # 20. Elastic Beanstalk
    try:
        eb = session.client('elasticbeanstalk', region_name=region)
        for env in eb.describe_environments(IncludeDeleted=False).get('Environments', []):
            try:
                settings = eb.describe_configuration_settings(
                    ApplicationName=env['ApplicationName'],
                    EnvironmentName=env['EnvironmentName']
                )['ConfigurationSettings'][0]
                for opt in settings.get('OptionSettings', []):
                    if 'SecurityGroups' in opt.get('OptionName', ''):
                        for sg in _SG_PATTERN.findall(opt.get('Value', '')):
                            _add(attach_map, sg, 'elasticbeanstalk', 'environment', env['EnvironmentName'])
            except Exception:
                pass
    except Exception:
        pass

    # 21. VPC Endpoints
    try:
        ec2 = session.client('ec2', region_name=region)
        for page in ec2.get_paginator('describe_vpc_endpoints').paginate():
            for ep in page['VpcEndpoints']:
                for sg in ep.get('Groups', []):
                    _add(attach_map, sg.get('GroupId', ''), 'ec2', 'vpc_endpoint', ep['VpcEndpointId'], ep.get('ServiceName'))
    except Exception:
        pass

    return attach_map
