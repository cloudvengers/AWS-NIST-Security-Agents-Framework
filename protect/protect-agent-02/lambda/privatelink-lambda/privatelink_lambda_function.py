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
        
        # PrivateLink 보안 데이터 병렬 수집
        raw_data = collect_privatelink_raw_data_parallel(ec2_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzePrivateLinkSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"PrivateLink 보안 분석 함수 실행 중 오류 발생: {str(e)}"
        print(error_message)
        return create_bedrock_error_response(event, error_message)

def collect_privatelink_raw_data_parallel(ec2_client, target_region):
    """PrivateLink 보안 관련 원시 데이터를 병렬로 수집"""
    
    # 1단계: 기본 PrivateLink 리소스 목록 수집
    vpc_endpoints = get_all_vpc_endpoints(ec2_client)
    endpoint_service_configs = get_all_endpoint_service_configurations(ec2_client)
    available_services = get_available_endpoint_services(ec2_client)
    
    # 2단계: 각 리소스별 상세 정보 병렬 수집
    vpc_endpoints_details = process_vpc_endpoints_parallel(ec2_client, vpc_endpoints)
    endpoint_services_details = process_endpoint_services_parallel(ec2_client, endpoint_service_configs)
    
    # 수집 요약 정보
    collection_summary = {
        'total_vpc_endpoints': len(vpc_endpoints),
        'total_endpoint_services': len(endpoint_service_configs),
        'total_available_services': len(available_services),
        'target_region': target_region,
        'collection_timestamp': 'now',
        'apis_used': 5
    }
    
    return {
        'vpc_endpoints_analysis': vpc_endpoints_details,
        'endpoint_services_analysis': endpoint_services_details,
        'available_services': available_services,
        'collection_summary': collection_summary
    }

def get_all_vpc_endpoints(ec2_client):
    """모든 VPC 엔드포인트 목록 조회 (API 4)"""
    try:
        paginator = ec2_client.get_paginator('describe_vpc_endpoints')
        vpc_endpoints = []
        for page in paginator.paginate():
            vpc_endpoints.extend(page.get('VpcEndpoints', []))
        return vpc_endpoints
    except Exception as e:
        print(f"Error getting VPC endpoints: {str(e)}")
        return []

def get_all_endpoint_service_configurations(ec2_client):
    """모든 VPC 엔드포인트 서비스 구성 조회 (API 2)"""
    try:
        paginator = ec2_client.get_paginator('describe_vpc_endpoint_service_configurations')
        service_configs = []
        for page in paginator.paginate():
            service_configs.extend(page.get('ServiceConfigurations', []))
        return service_configs
    except Exception as e:
        print(f"Error getting endpoint service configurations: {str(e)}")
        return []

def get_available_endpoint_services(ec2_client):
    """사용 가능한 VPC 엔드포인트 서비스 조회 (API 5)"""
    try:
        paginator = ec2_client.get_paginator('describe_vpc_endpoint_services')
        available_services = []
        for page in paginator.paginate():
            available_services.extend(page.get('ServiceDetails', []))
        return available_services
    except Exception as e:
        print(f"Error getting available endpoint services: {str(e)}")
        return []

def process_vpc_endpoints_parallel(ec2_client, vpc_endpoints):
    """VPC 엔드포인트별 상세 보안 정보를 병렬로 수집"""
    if not vpc_endpoints:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_vpc_endpoint_security_details, ec2_client, endpoint) for endpoint in vpc_endpoints]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing VPC endpoint: {str(e)}")
                continue
    
    return results

def get_vpc_endpoint_security_details(ec2_client, vpc_endpoint):
    """개별 VPC 엔드포인트의 보안 상세 정보 수집"""
    try:
        endpoint_id = vpc_endpoint['VpcEndpointId']
        endpoint_details = {
            'vpc_endpoint_info': vpc_endpoint,
            'security_analysis': {
                'endpoint_type': vpc_endpoint.get('VpcEndpointType'),
                'state': vpc_endpoint.get('State'),
                'policy_document': vpc_endpoint.get('PolicyDocument'),
                'route_table_ids': vpc_endpoint.get('RouteTableIds', []),
                'subnet_ids': vpc_endpoint.get('SubnetIds', []),
                'security_group_ids': vpc_endpoint.get('Groups', []),
                'private_dns_enabled': vpc_endpoint.get('PrivateDnsEnabled', False),
                'creation_timestamp': vpc_endpoint.get('CreationTimestamp'),
                'tags': vpc_endpoint.get('Tags', [])
            },
            'connections': []
        }
        
        # VPC 엔드포인트 연결 상태 및 보안 설정 조회 (API 3)
        try:
            connections = ec2_client.describe_vpc_endpoint_connections(
                Filters=[
                    {
                        'Name': 'vpc-endpoint-id',
                        'Values': [endpoint_id]
                    }
                ]
            )
            endpoint_details['connections'] = connections.get('VpcEndpointConnections', [])
        except Exception as e:
            endpoint_details['connections'] = {'Error': str(e)}
        
        # 보안 분석 추가
        endpoint_details['security_analysis']['security_assessment'] = analyze_endpoint_security(vpc_endpoint)
        
        return endpoint_details
        
    except Exception as e:
        print(f"Error getting VPC endpoint details for {vpc_endpoint.get('VpcEndpointId', 'unknown')}: {str(e)}")
        return None

def analyze_endpoint_security(vpc_endpoint):
    """VPC 엔드포인트 보안 평가"""
    security_assessment = {
        'policy_analysis': {},
        'network_security': {},
        'access_control': {}
    }
    
    # 1. 정책 분석
    policy_doc = vpc_endpoint.get('PolicyDocument')
    if policy_doc:
        try:
            if isinstance(policy_doc, str):
                policy = json.loads(policy_doc)
            else:
                policy = policy_doc
            
            security_assessment['policy_analysis'] = {
                'has_policy': True,
                'policy_statements': len(policy.get('Statement', [])),
                'allows_all_principals': any(
                    stmt.get('Principal') == '*' for stmt in policy.get('Statement', [])
                ),
                'policy_document': policy
            }
        except Exception as e:
            security_assessment['policy_analysis'] = {
                'has_policy': True,
                'parsing_error': str(e)
            }
    else:
        security_assessment['policy_analysis'] = {
            'has_policy': False,
            'note': 'No resource policy attached - uses default permissions'
        }
    
    # 2. 네트워크 보안 분석
    security_assessment['network_security'] = {
        'endpoint_type': vpc_endpoint.get('VpcEndpointType'),
        'private_dns_enabled': vpc_endpoint.get('PrivateDnsEnabled', False),
        'security_groups_count': len(vpc_endpoint.get('Groups', [])),
        'subnets_count': len(vpc_endpoint.get('SubnetIds', [])),
        'route_tables_count': len(vpc_endpoint.get('RouteTableIds', []))
    }
    
    # 3. 접근 제어 분석
    security_assessment['access_control'] = {
        'vpc_id': vpc_endpoint.get('VpcId'),
        'owner_id': vpc_endpoint.get('OwnerId'),
        'service_name': vpc_endpoint.get('ServiceName'),
        'requester_managed': vpc_endpoint.get('RequesterManaged', False)
    }
    
    return security_assessment

def process_endpoint_services_parallel(ec2_client, endpoint_service_configs):
    """엔드포인트 서비스별 상세 보안 정보를 병렬로 수집"""
    if not endpoint_service_configs:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_endpoint_service_security_details, ec2_client, service) for service in endpoint_service_configs]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing endpoint service: {str(e)}")
                continue
    
    return results

def get_endpoint_service_security_details(ec2_client, endpoint_service):
    """개별 엔드포인트 서비스의 보안 상세 정보 수집"""
    try:
        service_id = endpoint_service.get('ServiceId')
        service_name = endpoint_service.get('ServiceName')
        
        service_details = {
            'endpoint_service_info': endpoint_service,
            'permissions': [],
            'security_analysis': {
                'service_state': endpoint_service.get('ServiceState'),
                'acceptance_required': endpoint_service.get('AcceptanceRequired', False),
                'manages_vpc_endpoints': endpoint_service.get('ManagesVpcEndpoints', False),
                'supported_policy_types': endpoint_service.get('PayerResponsibility'),
                'tags': endpoint_service.get('Tags', [])
            }
        }
        
        # VPC 엔드포인트 서비스 접근 권한 조회 (API 1)
        try:
            if service_id:
                permissions = ec2_client.describe_vpc_endpoint_service_permissions(
                    ServiceId=service_id
                )
                service_details['permissions'] = permissions.get('AllowedPrincipals', [])
            else:
                service_details['permissions'] = {'Note': 'Service ID not available'}
        except Exception as e:
            service_details['permissions'] = {'Error': str(e)}
        
        # 보안 분석 추가
        service_details['security_analysis']['security_assessment'] = analyze_service_security(endpoint_service, service_details['permissions'])
        
        return service_details
        
    except Exception as e:
        print(f"Error getting endpoint service details for {endpoint_service.get('ServiceName', 'unknown')}: {str(e)}")
        return None

def analyze_service_security(endpoint_service, permissions):
    """엔드포인트 서비스 보안 평가"""
    security_assessment = {
        'access_control': {},
        'service_configuration': {},
        'permission_analysis': {}
    }
    
    # 1. 접근 제어 분석
    security_assessment['access_control'] = {
        'acceptance_required': endpoint_service.get('AcceptanceRequired', False),
        'owner_id': endpoint_service.get('Owner'),
        'base_endpoint_dns_names': endpoint_service.get('BaseEndpointDnsNames', []),
        'private_dns_name': endpoint_service.get('PrivateDnsName')
    }
    
    # 2. 서비스 구성 분석
    security_assessment['service_configuration'] = {
        'service_type': endpoint_service.get('ServiceType', []),
        'availability_zones': endpoint_service.get('AvailabilityZones', []),
        'network_load_balancer_arns': endpoint_service.get('NetworkLoadBalancerArns', []),
        'gateway_load_balancer_arns': endpoint_service.get('GatewayLoadBalancerArns', [])
    }
    
    # 3. 권한 분석
    if isinstance(permissions, list):
        security_assessment['permission_analysis'] = {
            'total_allowed_principals': len(permissions),
            'has_wildcard_access': any(
                principal.get('Principal') == '*' for principal in permissions
            ),
            'cross_account_access': any(
                principal.get('Principal', '').startswith('arn:aws:iam::') and 
                principal.get('Principal', '').split(':')[4] != endpoint_service.get('Owner', '')
                for principal in permissions
            ),
            'allowed_principals': permissions
        }
    else:
        security_assessment['permission_analysis'] = {
            'permissions_error': permissions
        }
    
    return security_assessment

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
