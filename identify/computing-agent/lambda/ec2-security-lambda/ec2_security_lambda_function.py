import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    IDENTIFY-AGENT-02 EC2 Security Analysis Lambda 함수
    25개 EC2 API를 통한 종합적인 EC2 보안 상태 분석
    """
    try:
        # 파라미터 추출
        parameters = event.get('parameters', [])
        param_dict = {param['name']: param['value'] for param in parameters}
        target_region = param_dict.get('target_region', 'us-east-1')
        
        # 세션 속성에서 고객 자격증명 및 현재 시간 획득
        session_attributes = event.get('sessionAttributes', {})
        access_key = session_attributes.get('access_key')
        secret_key = session_attributes.get('secret_key')
        current_time = session_attributes.get('current_time', datetime.utcnow().isoformat())
        
        if not access_key or not secret_key:
            return create_bedrock_error_response(event, "고객 자격증명이 제공되지 않았습니다. 세션을 다시 시작해주세요.")
        
        # 고객 자격증명으로 AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        
        ec2_client = session.client('ec2', region_name=target_region)
        
        # EC2 보안 분석 데이터 수집 (병렬 처리)
        raw_data = collect_ec2_security_data_parallel(ec2_client, target_region, current_time)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeEc2Security',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"EC2 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in EC2 security analysis lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_ec2_security_data_parallel(client, target_region, current_time):
    """
    EC2 보안 데이터를 병렬로 수집 - 25개 API 활용
    """
    # 먼저 인스턴스 목록 조회
    try:
        instances_response = client.describe_instances()
        reservations = instances_response.get('Reservations', [])
        all_instances = []
        for reservation in reservations:
            all_instances.extend(reservation.get('Instances', []))
    except Exception as e:
        print(f"Error listing EC2 instances: {str(e)}")
        return {
            'function': 'analyzeEc2Security',
            'target_region': target_region,
            'status': 'error',
            'message': f'EC2 인스턴스 목록 조회 실패: {str(e)}',
            'collection_summary': {
                'instances_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    if not all_instances:
        return {
            'function': 'analyzeEc2Security',
            'target_region': target_region,
            'status': 'no_instances',
            'message': 'EC2 인스턴스가 존재하지 않습니다.',
            'collection_summary': {
                'instances_found': 0,
                'apis_called': 1,
                'collection_method': 'parallel_processing'
            }
        }
    
    # 병렬 데이터 수집 작업 정의
    collection_tasks = [
        ('instances_security_analysis', lambda: analyze_instances_security_parallel(client, all_instances)),
        ('network_security_analysis', lambda: analyze_network_security_parallel(client)),
        ('storage_security_analysis', lambda: analyze_storage_security_parallel(client)),
        ('account_security_settings', lambda: get_account_security_settings_parallel(client)),
    ]
    
    # 병렬 처리 실행
    results = process_ec2_parallel(collection_tasks)
    
    # 수집 요약 생성
    collection_summary = {
        'instances_analyzed': len(all_instances),
        'target_region': target_region,
        'data_categories_collected': len([k for k, v in results.items() if v is not None]),
        'total_apis_called': calculate_total_ec2_apis_called(all_instances),
        'collection_method': 'parallel_processing',
        'instance_ids_analyzed': [i['InstanceId'] for i in all_instances[:10]]  # 최대 10개만 표시
    }
    
    return {
        'function': 'analyzeEc2Security',
        'target_region': target_region,
        'collection_timestamp': current_time,
        'analysis_time': current_time,
        'instances_data': results.get('instances_security_analysis', {}),
        'network_security': results.get('network_security_analysis', {}),
        'storage_security': results.get('storage_security_analysis', {}),
        'account_settings': results.get('account_security_settings', {}),
        'collection_summary': collection_summary
    }

def process_ec2_parallel(tasks, max_workers=4):
    """EC2 데이터 수집 작업을 병렬로 처리"""
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(task_func): task_name for task_name, task_func in tasks}
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                results[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                results[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results
def analyze_instances_security_parallel(client, instances, max_workers=5):
    """인스턴스들의 보안 설정을 병렬로 분석"""
    # 실행 중인 인스턴스만 분석 (최대 20개)
    running_instances = [i for i in instances if i.get('State', {}).get('Name') == 'running'][:20]
    
    instance_analyses = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_single_instance_security, client, instance) for instance in running_instances]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    instance_analyses.append(result)
            except Exception as e:
                print(f"Error analyzing instance: {str(e)}")
                continue
    
    return {
        'total_instances': len(instances),
        'running_instances': len(running_instances),
        'analyzed_instances': len(instance_analyses),
        'instance_security_details': instance_analyses
    }

def analyze_single_instance_security(client, instance):
    """개별 인스턴스의 보안 설정 종합 분석"""
    instance_id = instance['InstanceId']
    
    try:
        # 인스턴스 보안 분석 데이터 수집
        security_tasks = [
            ('metadata_options', lambda: get_instance_metadata_options_safe(client, instance_id)),
            ('instance_status', lambda: get_instance_status_safe(client, instance_id)),
            ('console_output', lambda: get_console_output_safe(client, instance_id)),
            ('iam_profile', lambda: get_iam_instance_profile_safe(client, instance_id)),
            ('instance_attributes', lambda: get_instance_attributes_safe(client, instance_id))
        ]
        
        security_data = execute_parallel_tasks(security_tasks, max_workers=5)
        
        # 인스턴스 기본 보안 설정 분석
        basic_security = analyze_instance_basic_security(instance)
        
        return {
            'instance_id': instance_id,
            'instance_type': instance.get('InstanceType'),
            'state': instance.get('State', {}).get('Name'),
            'launch_time': instance.get('LaunchTime'),
            'basic_security': basic_security,
            'metadata_options': security_data.get('metadata_options', {}),
            'instance_status': security_data.get('instance_status', {}),
            'console_output': security_data.get('console_output', {}),
            'iam_profile': security_data.get('iam_profile', {}),
            'instance_attributes': security_data.get('instance_attributes', {})
        }
        
    except Exception as e:
        print(f"Error analyzing instance {instance_id}: {str(e)}")
        return {
            'instance_id': instance_id,
            'status': 'error',
            'error_message': str(e)
        }

def analyze_instance_basic_security(instance):
    """인스턴스 기본 보안 설정 분석"""
    return {
        'public_ip_address': instance.get('PublicIpAddress'),
        'private_ip_address': instance.get('PrivateIpAddress'),
        'has_public_ip': instance.get('PublicIpAddress') is not None,
        'vpc_id': instance.get('VpcId'),
        'subnet_id': instance.get('SubnetId'),
        'security_groups': instance.get('SecurityGroups', []),
        'key_name': instance.get('KeyName'),
        'platform': instance.get('Platform'),
        'architecture': instance.get('Architecture'),
        'virtualization_type': instance.get('VirtualizationType'),
        'hypervisor': instance.get('Hypervisor'),
        'source_dest_check': instance.get('SourceDestCheck'),
        'ebs_optimized': instance.get('EbsOptimized'),
        'ena_support': instance.get('EnaSupport'),
        'sriov_net_support': instance.get('SriovNetSupport'),
        'block_device_mappings': instance.get('BlockDeviceMappings', []),
        'network_interfaces': instance.get('NetworkInterfaces', []),
        'tags': instance.get('Tags', [])
    }

def analyze_network_security_parallel(client):
    """네트워크 보안 설정 분석 (7개 API)"""
    network_tasks = [
        ('security_groups', lambda: analyze_security_groups_safe(client)),
        ('network_acls', lambda: analyze_network_acls_safe(client)),
        ('addresses', lambda: get_addresses_safe(client)),
        ('network_interfaces', lambda: get_network_interfaces_safe(client)),
        ('subnets', lambda: get_subnets_safe(client)),
        ('internet_gateways', lambda: get_internet_gateways_safe(client)),
        ('vpc_endpoints', lambda: get_vpc_endpoints_safe(client))
    ]
    
    return execute_parallel_tasks(network_tasks, max_workers=7)

def analyze_storage_security_parallel(client):
    """스토리지 보안 설정 분석 (5개 API)"""
    storage_tasks = [
        ('volumes', lambda: analyze_volumes_safe(client)),
        ('snapshots', lambda: analyze_snapshots_safe(client)),
        ('ebs_encryption_default', lambda: get_ebs_encryption_default_safe(client)),
        ('volume_attributes', lambda: get_volume_attributes_safe(client)),
        ('snapshot_attributes', lambda: get_snapshot_attributes_safe(client))
    ]
    
    return execute_parallel_tasks(storage_tasks, max_workers=5)

def get_account_security_settings_parallel(client):
    """계정 보안 설정 분석 (3개 API)"""
    account_tasks = [
        ('key_pairs', lambda: get_key_pairs_safe(client)),
        ('images', lambda: get_images_safe(client)),
        ('tags', lambda: get_tags_safe(client))
    ]
    
    return execute_parallel_tasks(account_tasks, max_workers=3)

# 인스턴스별 보안 API 안전 호출 함수들
def get_instance_metadata_options_safe(client, instance_id):
    """DescribeInstanceMetadataOptions 안전 호출"""
    try:
        response = client.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute='instanceMetadataOptions'
        )
        metadata_options = response.get('InstanceMetadataOptions', {})
        
        return {
            'http_tokens': metadata_options.get('HttpTokens'),
            'http_put_response_hop_limit': metadata_options.get('HttpPutResponseHopLimit'),
            'http_endpoint': metadata_options.get('HttpEndpoint'),
            'http_protocol_ipv6': metadata_options.get('HttpProtocolIpv6'),
            'instance_metadata_tags': metadata_options.get('InstanceMetadataTags'),
            'imdsv2_required': metadata_options.get('HttpTokens') == 'required'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_instance_status_safe(client, instance_id):
    """DescribeInstanceStatus 안전 호출"""
    try:
        response = client.describe_instance_status(InstanceIds=[instance_id])
        statuses = response.get('InstanceStatuses', [])
        
        if not statuses:
            return {'has_status': False, 'message': '인스턴스 상태 정보가 없습니다.'}
        
        status = statuses[0]
        return {
            'has_status': True,
            'instance_state': status.get('InstanceState', {}),
            'instance_status': status.get('InstanceStatus', {}),
            'system_status': status.get('SystemStatus', {}),
            'events': status.get('Events', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_console_output_safe(client, instance_id):
    """GetConsoleOutput 안전 호출"""
    try:
        response = client.get_console_output(InstanceId=instance_id)
        return {
            'has_console_output': True,
            'output_length': len(response.get('Output', '')),
            'timestamp': response.get('Timestamp'),
            'output_sample': response.get('Output', '')[:500]  # 처음 500자만
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_iam_instance_profile_safe(client, instance_id):
    """DescribeIamInstanceProfileAssociations 안전 호출"""
    try:
        response = client.describe_iam_instance_profile_associations(
            Filters=[
                {
                    'Name': 'instance-id',
                    'Values': [instance_id]
                }
            ]
        )
        associations = response.get('IamInstanceProfileAssociations', [])
        
        return {
            'has_iam_profile': len(associations) > 0,
            'associations': associations
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_instance_attributes_safe(client, instance_id):
    """DescribeInstanceAttribute 안전 호출 (여러 속성)"""
    try:
        attributes = {}
        attribute_names = ['instanceType', 'kernel', 'ramdisk', 'userData', 'disableApiTermination', 
                          'instanceInitiatedShutdownBehavior', 'rootDeviceName', 'blockDeviceMapping']
        
        for attr_name in attribute_names:
            try:
                response = client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute=attr_name
                )
                attributes[attr_name] = response.get(attr_name.title(), {})
            except Exception as e:
                attributes[attr_name] = {'error': str(e)}
        
        return attributes
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
# 네트워크 보안 API 안전 호출 함수들
def analyze_security_groups_safe(client):
    """DescribeSecurityGroups + DescribeSecurityGroupRules + DescribeStaleSecurityGroups 안전 호출"""
    try:
        # DescribeSecurityGroups
        sg_response = client.describe_security_groups()
        security_groups = sg_response.get('SecurityGroups', [])
        
        # 보안 그룹 분석
        risky_sgs = []
        for sg in security_groups:
            # 위험한 인바운드 규칙 확인 (0.0.0.0/0 허용)
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        risky_sgs.append({
                            'group_id': sg.get('GroupId'),
                            'group_name': sg.get('GroupName'),
                            'risky_rule': rule
                        })
        
        # DescribeStaleSecurityGroups (VPC별로)
        stale_sgs = []
        try:
            vpcs_response = client.describe_vpcs()
            for vpc in vpcs_response.get('Vpcs', []):
                vpc_id = vpc.get('VpcId')
                try:
                    stale_response = client.describe_stale_security_groups(VpcId=vpc_id)
                    stale_sgs.extend(stale_response.get('StaleSecurityGroupSet', []))
                except Exception as e:
                    print(f"Error getting stale security groups for VPC {vpc_id}: {str(e)}")
        except Exception as e:
            print(f"Error getting VPCs for stale security group check: {str(e)}")
        
        return {
            'total_security_groups': len(security_groups),
            'risky_security_groups': risky_sgs,
            'stale_security_groups': stale_sgs,
            'security_groups_sample': security_groups[:5]  # 처음 5개만
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_network_acls_safe(client):
    """DescribeNetworkAcls 안전 호출"""
    try:
        response = client.describe_network_acls()
        network_acls = response.get('NetworkAcls', [])
        
        # 기본이 아닌 NACL 분석
        custom_nacls = [nacl for nacl in network_acls if not nacl.get('IsDefault', True)]
        
        return {
            'total_network_acls': len(network_acls),
            'custom_network_acls': len(custom_nacls),
            'network_acls_sample': network_acls[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_addresses_safe(client):
    """DescribeAddresses 안전 호출"""
    try:
        response = client.describe_addresses()
        addresses = response.get('Addresses', [])
        
        # 연결되지 않은 Elastic IP 확인
        unattached_eips = [addr for addr in addresses if not addr.get('InstanceId')]
        
        return {
            'total_elastic_ips': len(addresses),
            'unattached_elastic_ips': len(unattached_eips),
            'addresses_details': addresses
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_network_interfaces_safe(client):
    """DescribeNetworkInterfaces 안전 호출"""
    try:
        response = client.describe_network_interfaces()
        network_interfaces = response.get('NetworkInterfaces', [])
        
        # 퍼블릭 IP가 있는 네트워크 인터페이스
        public_interfaces = [ni for ni in network_interfaces if ni.get('Association', {}).get('PublicIp')]
        
        return {
            'total_network_interfaces': len(network_interfaces),
            'public_network_interfaces': len(public_interfaces),
            'network_interfaces_sample': network_interfaces[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_subnets_safe(client):
    """DescribeSubnets 안전 호출"""
    try:
        response = client.describe_subnets()
        subnets = response.get('Subnets', [])
        
        # 퍼블릭 IP 자동 할당 서브넷
        auto_public_subnets = [subnet for subnet in subnets if subnet.get('MapPublicIpOnLaunch')]
        
        return {
            'total_subnets': len(subnets),
            'auto_public_ip_subnets': len(auto_public_subnets),
            'subnets_sample': subnets[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_internet_gateways_safe(client):
    """DescribeInternetGateways 안전 호출"""
    try:
        response = client.describe_internet_gateways()
        internet_gateways = response.get('InternetGateways', [])
        
        return {
            'total_internet_gateways': len(internet_gateways),
            'internet_gateways_details': internet_gateways
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_vpc_endpoints_safe(client):
    """DescribeVpcEndpoints 안전 호출"""
    try:
        response = client.describe_vpc_endpoints()
        vpc_endpoints = response.get('VpcEndpoints', [])
        
        return {
            'total_vpc_endpoints': len(vpc_endpoints),
            'vpc_endpoints_sample': vpc_endpoints[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 스토리지 보안 API 안전 호출 함수들
def analyze_volumes_safe(client):
    """DescribeVolumes 안전 호출"""
    try:
        response = client.describe_volumes()
        volumes = response.get('Volumes', [])
        
        # 암호화되지 않은 볼륨 확인
        unencrypted_volumes = [vol for vol in volumes if not vol.get('Encrypted', False)]
        
        return {
            'total_volumes': len(volumes),
            'unencrypted_volumes': len(unencrypted_volumes),
            'volumes_sample': volumes[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def analyze_snapshots_safe(client):
    """DescribeSnapshots 안전 호출"""
    try:
        # 자신의 스냅샷만 조회
        response = client.describe_snapshots(OwnerIds=['self'])
        snapshots = response.get('Snapshots', [])
        
        # 암호화되지 않은 스냅샷 확인
        unencrypted_snapshots = [snap for snap in snapshots if not snap.get('Encrypted', False)]
        
        return {
            'total_snapshots': len(snapshots),
            'unencrypted_snapshots': len(unencrypted_snapshots),
            'snapshots_sample': snapshots[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_ebs_encryption_default_safe(client):
    """GetEbsEncryptionByDefault 안전 호출"""
    try:
        response = client.get_ebs_encryption_by_default()
        return {
            'ebs_encryption_by_default': response.get('EbsEncryptionByDefault', False)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_volume_attributes_safe(client):
    """DescribeVolumeAttribute 안전 호출 (샘플 볼륨)"""
    try:
        # 먼저 볼륨 목록 조회
        volumes_response = client.describe_volumes(MaxResults=5)
        volumes = volumes_response.get('Volumes', [])
        
        if not volumes:
            return {'has_volumes': False, 'message': '볼륨이 없습니다.'}
        
        # 첫 번째 볼륨의 속성 확인
        volume_id = volumes[0]['VolumeId']
        response = client.describe_volume_attribute(
            VolumeId=volume_id,
            Attribute='autoEnableIO'
        )
        
        return {
            'sample_volume_id': volume_id,
            'auto_enable_io': response.get('AutoEnableIO', {})
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_snapshot_attributes_safe(client):
    """DescribeSnapshotAttribute 안전 호출 (샘플 스냅샷)"""
    try:
        # 먼저 스냅샷 목록 조회
        snapshots_response = client.describe_snapshots(OwnerIds=['self'], MaxResults=5)
        snapshots = snapshots_response.get('Snapshots', [])
        
        if not snapshots:
            return {'has_snapshots': False, 'message': '스냅샷이 없습니다.'}
        
        # 첫 번째 스냅샷의 속성 확인
        snapshot_id = snapshots[0]['SnapshotId']
        response = client.describe_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute='createVolumePermission'
        )
        
        return {
            'sample_snapshot_id': snapshot_id,
            'create_volume_permissions': response.get('CreateVolumePermissions', [])
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 계정 보안 설정 API 안전 호출 함수들
def get_key_pairs_safe(client):
    """DescribeKeyPairs 안전 호출"""
    try:
        response = client.describe_key_pairs()
        key_pairs = response.get('KeyPairs', [])
        
        return {
            'total_key_pairs': len(key_pairs),
            'key_pairs_details': key_pairs
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_images_safe(client):
    """DescribeImages 안전 호출 (자신의 AMI만)"""
    try:
        response = client.describe_images(Owners=['self'])
        images = response.get('Images', [])
        
        return {
            'total_custom_images': len(images),
            'images_sample': images[:5]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_tags_safe(client):
    """DescribeTags 안전 호출"""
    try:
        response = client.describe_tags(MaxResults=100)
        tags = response.get('Tags', [])
        
        # 보안 관련 태그 분석
        security_tags = [tag for tag in tags if 'security' in tag.get('Key', '').lower()]
        
        return {
            'total_tags_sample': len(tags),
            'security_related_tags': len(security_tags),
            'tags_sample': tags[:10]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
def execute_parallel_tasks(tasks, max_workers=5):
    """병렬 작업 실행 헬퍼 함수"""
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(task_func): task_name for task_name, task_func in tasks}
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                results[task_name] = result
            except Exception as e:
                print(f"Error in {task_name}: {str(e)}")
                results[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def calculate_total_ec2_apis_called(instances):
    """총 API 호출 수 계산"""
    # 기본 API: DescribeInstances(1)
    base_apis = 1
    
    # 인스턴스당 API: DescribeInstanceAttribute(메타데이터)(1) + DescribeInstanceStatus(1) + 
    #                GetConsoleOutput(1) + DescribeIamInstanceProfileAssociations(1) + 
    #                DescribeInstanceAttribute(여러속성)(8)
    instance_apis = min(len(instances), 20) * 12  # 최대 20개 인스턴스만 분석
    
    # 네트워크 보안 API: DescribeSecurityGroups(1) + DescribeSecurityGroupRules(1) + 
    #                   DescribeStaleSecurityGroups(VPC수) + DescribeNetworkAcls(1) + 
    #                   DescribeAddresses(1) + DescribeNetworkInterfaces(1) + 
    #                   DescribeSubnets(1) + DescribeInternetGateways(1) + DescribeVpcEndpoints(1)
    network_apis = 9
    
    # 스토리지 보안 API: DescribeVolumes(1) + DescribeSnapshots(1) + GetEbsEncryptionByDefault(1) + 
    #                   DescribeVolumeAttribute(1) + DescribeSnapshotAttribute(1)
    storage_apis = 5
    
    # 계정 설정 API: DescribeKeyPairs(1) + DescribeImages(1) + DescribeTags(1)
    account_apis = 3
    
    return base_apis + instance_apis + network_apis + storage_apis + account_apis

def create_bedrock_success_response(event, response_data):
    """Bedrock Agent 성공 응답 생성"""
    response_body = {
        'TEXT': {
            'body': json.dumps(response_data, ensure_ascii=False, indent=2, default=str)
        }
    }
    
    function_response = {
        'actionGroup': event['actionGroup'],
        'function': event['function'],
        'functionResponse': {
            'responseBody': response_body
        }
    }
    
    return {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': event.get('sessionAttributes', {}),
        'promptSessionAttributes': event.get('promptSessionAttributes', {})
    }

def create_bedrock_error_response(event, error_message):
    """Bedrock Agent 에러 응답 생성"""
    error_data = {
        'function': event.get('function', 'analyzeEc2Security'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'ec2-security-analysis'),
        'function': event.get('function', 'analyzeEc2Security'),
        'functionResponse': {
            'responseState': 'FAILURE',
            'responseBody': response_body
        }
    }
    
    return {
        'messageVersion': '1.0',
        'response': function_response,
        'sessionAttributes': event.get('sessionAttributes', {}),
        'promptSessionAttributes': event.get('promptSessionAttributes', {})
    }
