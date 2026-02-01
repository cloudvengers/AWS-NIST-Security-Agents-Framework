import json
import boto3
import concurrent.futures
from datetime import datetime
from botocore.exceptions import ClientError

def lambda_handler(event, context):
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
            return create_bedrock_error_response(event, "고객 자격증명이 제공되지 않았습니다.")
        
        # 고객 자격증명으로 AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        
        ec2_client = session.client('ec2', region_name=target_region)
        
        # VPC 보안 데이터 병렬 수집
        raw_data = collect_vpc_raw_data_parallel(ec2_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeVPCSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"VPC 보안 분석 함수 실행 중 오류 발생: {str(e)}"
        print(error_message)
        return create_bedrock_error_response(event, error_message)

def collect_vpc_raw_data_parallel(ec2_client, target_region):
    """VPC 보안 관련 원시 데이터를 병렬로 수집"""
    
    # 1단계: 기본 VPC 리소스 목록 수집
    vpcs = get_all_vpcs(ec2_client)
    subnets = get_all_subnets(ec2_client)
    security_groups = get_all_security_groups(ec2_client)
    network_acls = get_all_network_acls(ec2_client)
    
    # 2단계: 각 리소스별 상세 정보 병렬 수집
    vpc_details = process_vpcs_parallel(ec2_client, vpcs)
    security_groups_details = process_security_groups_parallel(ec2_client, security_groups)
    network_acls_details = process_network_acls_parallel(ec2_client, network_acls)
    
    # 3단계: VPC 레벨 보안 기능 수집
    vpc_security_features = get_vpc_security_features(ec2_client, vpcs)
    
    # 4단계: 네트워크 모니터링 및 트래픽 분석 기능 수집
    network_monitoring = get_network_monitoring_features(ec2_client)
    
    # 수집 요약 정보
    collection_summary = {
        'total_vpcs': len(vpcs),
        'total_subnets': len(subnets),
        'total_security_groups': len(security_groups),
        'total_network_acls': len(network_acls),
        'target_region': target_region,
        'collection_timestamp': 'now',
        'apis_used': 17
    }
    
    return {
        'vpcs_analysis': vpc_details,
        'subnets_analysis': subnets,
        'security_groups_analysis': security_groups_details,
        'network_acls_analysis': network_acls_details,
        'vpc_security_features': vpc_security_features,
        'network_monitoring': network_monitoring,
        'collection_summary': collection_summary
    }

def get_all_vpcs(ec2_client):
    """모든 VPC 목록 조회 (API 15)"""
    try:
        paginator = ec2_client.get_paginator('describe_vpcs')
        vpcs = []
        for page in paginator.paginate():
            vpcs.extend(page.get('Vpcs', []))
        return vpcs
    except Exception as e:
        print(f"Error getting VPCs: {str(e)}")
        return []

def get_all_subnets(ec2_client):
    """모든 서브넷 목록 조회 (API 16)"""
    try:
        paginator = ec2_client.get_paginator('describe_subnets')
        subnets = []
        for page in paginator.paginate():
            subnets.extend(page.get('Subnets', []))
        return subnets
    except Exception as e:
        print(f"Error getting subnets: {str(e)}")
        return []

def get_all_security_groups(ec2_client):
    """모든 보안 그룹 목록 조회 (API 3)"""
    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        security_groups = []
        for page in paginator.paginate():
            security_groups.extend(page.get('SecurityGroups', []))
        return security_groups
    except Exception as e:
        print(f"Error getting security groups: {str(e)}")
        return []

def get_all_network_acls(ec2_client):
    """모든 네트워크 ACL 목록 조회 (API 7)"""
    try:
        paginator = ec2_client.get_paginator('describe_network_acls')
        network_acls = []
        for page in paginator.paginate():
            network_acls.extend(page.get('NetworkAcls', []))
        return network_acls
    except Exception as e:
        print(f"Error getting network ACLs: {str(e)}")
        return []

def process_vpcs_parallel(ec2_client, vpcs):
    """VPC별 상세 보안 정보를 병렬로 수집"""
    if not vpcs:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_vpc_security_details, ec2_client, vpc) for vpc in vpcs]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing VPC: {str(e)}")
                continue
    
    return results

def get_vpc_security_details(ec2_client, vpc):
    """개별 VPC의 보안 상세 정보 수집"""
    try:
        vpc_id = vpc['VpcId']
        vpc_details = {
            'vpc_info': vpc,
            'public_access_options': None,
            'public_access_exclusions': [],
            'route_tables': [],
            'peering_connections': [],
            'flow_logs': []
        }
        
        # 1. VPC 퍼블릭 액세스 차단 옵션 조회 (API 1)
        try:
            public_access_options = ec2_client.describe_vpc_block_public_access_options(
                VpcIds=[vpc_id]
            )
            vpc_details['public_access_options'] = public_access_options.get('VpcBlockPublicAccessOptions', [])
        except Exception as e:
            # 이 기능이 지원되지 않는 리전이나 계정일 수 있음
            vpc_details['public_access_options'] = {'Error': str(e), 'Note': 'Feature may not be available in this region'}
        
        # 2. VPC 퍼블릭 액세스 차단 예외 조회 (API 2)
        try:
            public_access_exclusions = ec2_client.describe_vpc_block_public_access_exclusions(
                VpcIds=[vpc_id]
            )
            vpc_details['public_access_exclusions'] = public_access_exclusions.get('VpcBlockPublicAccessExclusions', [])
        except Exception as e:
            vpc_details['public_access_exclusions'] = {'Error': str(e), 'Note': 'Feature may not be available in this region'}
        
        # 3. 라우트 테이블 조회 (API 17)
        try:
            route_tables = ec2_client.describe_route_tables(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            vpc_details['route_tables'] = route_tables.get('RouteTables', [])
        except Exception as e:
            vpc_details['route_tables'] = {'Error': str(e)}
        
        # 4. VPC 피어링 연결 조회 (API 9)
        try:
            peering_connections = ec2_client.describe_vpc_peering_connections(
                Filters=[
                    {
                        'Name': 'requester-vpc-info.vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            # 수락자 VPC로도 검색
            accepter_peering = ec2_client.describe_vpc_peering_connections(
                Filters=[
                    {
                        'Name': 'accepter-vpc-info.vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            
            all_peering = peering_connections.get('VpcPeeringConnections', [])
            all_peering.extend(accepter_peering.get('VpcPeeringConnections', []))
            
            # 중복 제거
            unique_peering = []
            seen_ids = set()
            for peering in all_peering:
                if peering['VpcPeeringConnectionId'] not in seen_ids:
                    unique_peering.append(peering)
                    seen_ids.add(peering['VpcPeeringConnectionId'])
            
            vpc_details['peering_connections'] = unique_peering
        except Exception as e:
            vpc_details['peering_connections'] = {'Error': str(e)}
        
        # 5. VPC 플로우 로그 조회 (API 8)
        try:
            flow_logs = ec2_client.describe_flow_logs(
                Filters=[
                    {
                        'Name': 'resource-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            vpc_details['flow_logs'] = flow_logs.get('FlowLogs', [])
        except Exception as e:
            vpc_details['flow_logs'] = {'Error': str(e)}
        
        return vpc_details
        
    except Exception as e:
        print(f"Error getting VPC details for {vpc.get('VpcId', 'unknown')}: {str(e)}")
        return None

def process_security_groups_parallel(ec2_client, security_groups):
    """보안 그룹별 상세 보안 정보를 병렬로 수집"""
    if not security_groups:
        return []
    
    # 기본 보안 그룹 정보는 이미 수집됨 (API 3)
    # 추가 보안 그룹 관련 분석 수행
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_security_group_analysis, ec2_client, sg) for sg in security_groups]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing security group: {str(e)}")
                continue
    
    return results

def get_security_group_analysis(ec2_client, security_group):
    """개별 보안 그룹의 보안 분석"""
    try:
        sg_id = security_group['GroupId']
        sg_analysis = {
            'security_group_info': security_group,
            'references': [],
            'stale_rules': []
        }
        
        # 1. 보안 그룹 참조 관계 조회 (API 4)
        try:
            references = ec2_client.describe_security_group_references(
                GroupIds=[sg_id]
            )
            sg_analysis['references'] = references.get('SecurityGroupReferenceSet', [])
        except Exception as e:
            sg_analysis['references'] = {'Error': str(e)}
        
        # 2. 오래된/불필요한 보안 그룹 규칙 확인 (API 6)
        try:
            # VPC ID가 있는 경우에만 stale 규칙 검사
            if security_group.get('VpcId'):
                stale_groups = ec2_client.describe_stale_security_groups(
                    VpcId=security_group['VpcId']
                )
                # 현재 보안 그룹과 관련된 stale 규칙만 필터링
                sg_analysis['stale_rules'] = [
                    stale for stale in stale_groups.get('StaleSecurityGroupSet', [])
                    if stale.get('GroupId') == sg_id
                ]
            else:
                sg_analysis['stale_rules'] = []
        except Exception as e:
            sg_analysis['stale_rules'] = {'Error': str(e)}
        
        return sg_analysis
        
    except Exception as e:
        print(f"Error analyzing security group {security_group.get('GroupId', 'unknown')}: {str(e)}")
        return None

def process_network_acls_parallel(ec2_client, network_acls):
    """네트워크 ACL별 상세 보안 정보를 병렬로 수집"""
    # 네트워크 ACL 정보는 이미 기본 조회에서 충분한 정보를 포함하고 있음
    # 추가 분석이 필요한 경우 여기서 수행
    
    processed_acls = []
    for nacl in network_acls:
        nacl_analysis = {
            'network_acl_info': nacl,
            'security_analysis': {
                'is_default': nacl.get('IsDefault', False),
                'associated_subnets': len(nacl.get('Associations', [])),
                'inbound_rules_count': len([entry for entry in nacl.get('Entries', []) if not entry.get('Egress', True)]),
                'outbound_rules_count': len([entry for entry in nacl.get('Entries', []) if entry.get('Egress', True)]),
                'open_rules': []
            }
        }
        
        # 위험한 규칙 분석 (0.0.0.0/0 허용 등)
        for entry in nacl.get('Entries', []):
            if entry.get('CidrBlock') == '0.0.0.0/0' and entry.get('RuleAction') == 'allow':
                nacl_analysis['security_analysis']['open_rules'].append(entry)
        
        processed_acls.append(nacl_analysis)
    
    return processed_acls

def get_vpc_security_features(ec2_client, vpcs):
    """VPC 레벨 보안 기능 수집"""
    security_features = {
        'vpc_security_groups_summary': [],
        'network_interfaces': []
    }
    
    # 1. VPC별 보안 그룹 요약 (API 5)
    for vpc in vpcs:
        try:
            vpc_security_groups = ec2_client.get_security_groups_for_vpc(
                VpcId=vpc['VpcId']
            )
            security_features['vpc_security_groups_summary'].append({
                'vpc_id': vpc['VpcId'],
                'security_groups': vpc_security_groups.get('SecurityGroupForVpcs', [])
            })
        except Exception as e:
            security_features['vpc_security_groups_summary'].append({
                'vpc_id': vpc['VpcId'],
                'error': str(e)
            })
    
    # 2. 네트워크 인터페이스 보안 설정 조회 (API 13-14)
    try:
        network_interfaces = ec2_client.describe_network_interfaces()
        
        # 네트워크 인터페이스 권한도 함께 조회
        for ni in network_interfaces.get('NetworkInterfaces', []):
            try:
                ni_permissions = ec2_client.describe_network_interface_permissions(
                    NetworkInterfacePermissionIds=[],
                    Filters=[
                        {
                            'Name': 'network-interface-id',
                            'Values': [ni['NetworkInterfaceId']]
                        }
                    ]
                )
                ni['Permissions'] = ni_permissions.get('NetworkInterfacePermissions', [])
            except Exception as e:
                ni['Permissions'] = {'Error': str(e)}
        
        security_features['network_interfaces'] = network_interfaces.get('NetworkInterfaces', [])
    except Exception as e:
        security_features['network_interfaces'] = {'Error': str(e)}
    
    return security_features

def get_network_monitoring_features(ec2_client):
    """네트워크 모니터링 및 트래픽 분석 기능 수집"""
    monitoring_features = {
        'traffic_mirroring': {
            'sessions': [],
            'filters': [],
            'targets': []
        }
    }
    
    # 1. 트래픽 미러링 세션 조회 (API 10)
    try:
        mirror_sessions = ec2_client.describe_traffic_mirror_sessions()
        monitoring_features['traffic_mirroring']['sessions'] = mirror_sessions.get('TrafficMirrorSessions', [])
    except Exception as e:
        monitoring_features['traffic_mirroring']['sessions'] = {'Error': str(e)}
    
    # 2. 트래픽 미러링 필터 조회 (API 11)
    try:
        mirror_filters = ec2_client.describe_traffic_mirror_filters()
        monitoring_features['traffic_mirroring']['filters'] = mirror_filters.get('TrafficMirrorFilters', [])
    except Exception as e:
        monitoring_features['traffic_mirroring']['filters'] = {'Error': str(e)}
    
    # 3. 트래픽 미러링 대상 조회 (API 12)
    try:
        mirror_targets = ec2_client.describe_traffic_mirror_targets()
        monitoring_features['traffic_mirroring']['targets'] = mirror_targets.get('TrafficMirrorTargets', [])
    except Exception as e:
        monitoring_features['traffic_mirroring']['targets'] = {'Error': str(e)}
    
    return monitoring_features

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
        'function': event.get('function', 'unknown'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'unknown'),
        'function': event.get('function', 'unknown'),
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
