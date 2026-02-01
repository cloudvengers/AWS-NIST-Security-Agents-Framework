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
        
        # Transit Gateway 보안 데이터 병렬 수집
        raw_data = collect_transit_gateway_raw_data_parallel(ec2_client, target_region)
        
        # 수집된 데이터에 시간 정보 추가
        collected_data = {
            'function': 'analyzeTransitGatewaySecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time
        }
        collected_data.update(raw_data)
        
        return create_bedrock_success_response(event, collected_data)
        
    except Exception as e:
        error_message = f"Transit Gateway 보안 분석 함수 실행 중 오류 발생: {str(e)}"
        print(error_message)
        return create_bedrock_error_response(event, error_message)

def collect_transit_gateway_raw_data_parallel(ec2_client, target_region):
    """Transit Gateway 보안 관련 원시 데이터를 병렬로 수집"""
    
    # 1단계: 기본 Transit Gateway 목록 수집
    transit_gateways = get_all_transit_gateways(ec2_client)
    
    if not transit_gateways:
        return {
            'transit_gateways_analysis': [],
            'route_tables_analysis': [],
            'attachments_analysis': [],
            'collection_summary': {
                'total_transit_gateways': 0,
                'total_route_tables': 0,
                'total_attachments': 0,
                'target_region': target_region,
                'collection_timestamp': 'now',
                'apis_used': 8,
                'note': 'No Transit Gateways found in region'
            }
        }
    
    # 2단계: 각 Transit Gateway별 상세 정보 병렬 수집
    tgw_details = process_transit_gateways_parallel(ec2_client, transit_gateways)
    
    # 3단계: 라우트 테이블 정보 수집
    route_tables = get_all_route_tables(ec2_client)
    route_tables_details = process_route_tables_parallel(ec2_client, route_tables)
    
    # 4단계: 연결(Attachment) 정보 수집
    attachments = get_all_attachments(ec2_client)
    attachments_details = process_attachments_parallel(ec2_client, attachments)
    
    # 수집 요약 정보
    collection_summary = {
        'total_transit_gateways': len(transit_gateways),
        'total_route_tables': len(route_tables),
        'total_attachments': len(attachments),
        'target_region': target_region,
        'collection_timestamp': 'now',
        'apis_used': 8
    }
    
    return {
        'transit_gateways_analysis': tgw_details,
        'route_tables_analysis': route_tables_details,
        'attachments_analysis': attachments_details,
        'collection_summary': collection_summary
    }

def get_all_transit_gateways(ec2_client):
    """모든 Transit Gateway 목록 조회 (API 7)"""
    try:
        paginator = ec2_client.get_paginator('describe_transit_gateways')
        transit_gateways = []
        for page in paginator.paginate():
            transit_gateways.extend(page.get('TransitGateways', []))
        return transit_gateways
    except Exception as e:
        print(f"Error getting transit gateways: {str(e)}")
        return []

def get_all_route_tables(ec2_client):
    """모든 Transit Gateway 라우트 테이블 목록 조회 (API 1)"""
    try:
        paginator = ec2_client.get_paginator('describe_transit_gateway_route_tables')
        route_tables = []
        for page in paginator.paginate():
            route_tables.extend(page.get('TransitGatewayRouteTables', []))
        return route_tables
    except Exception as e:
        print(f"Error getting transit gateway route tables: {str(e)}")
        return []

def get_all_attachments(ec2_client):
    """모든 Transit Gateway 연결 목록 조회 (API 8)"""
    try:
        paginator = ec2_client.get_paginator('describe_transit_gateway_attachments')
        attachments = []
        for page in paginator.paginate():
            attachments.extend(page.get('TransitGatewayAttachments', []))
        return attachments
    except Exception as e:
        print(f"Error getting transit gateway attachments: {str(e)}")
        return []

def process_transit_gateways_parallel(ec2_client, transit_gateways):
    """Transit Gateway별 상세 보안 정보를 병렬로 수집"""
    if not transit_gateways:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_transit_gateway_security_details, ec2_client, tgw) for tgw in transit_gateways]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing transit gateway: {str(e)}")
                continue
    
    return results

def get_transit_gateway_security_details(ec2_client, transit_gateway):
    """개별 Transit Gateway의 보안 상세 정보 수집"""
    try:
        tgw_id = transit_gateway['TransitGatewayId']
        tgw_details = {
            'transit_gateway_info': transit_gateway,
            'vpc_attachments': [],
            'peering_attachments': []
        }
        
        # 1. VPC 연결 상태 및 설정 조회 (API 5)
        try:
            vpc_attachments = ec2_client.describe_transit_gateway_vpc_attachments(
                Filters=[
                    {
                        'Name': 'transit-gateway-id',
                        'Values': [tgw_id]
                    }
                ]
            )
            tgw_details['vpc_attachments'] = vpc_attachments.get('TransitGatewayVpcAttachments', [])
        except Exception as e:
            tgw_details['vpc_attachments'] = {'Error': str(e)}
        
        # 2. 피어링 연결 상태 조회 (API 6)
        try:
            peering_attachments = ec2_client.describe_transit_gateway_peering_attachments(
                Filters=[
                    {
                        'Name': 'transit-gateway-id',
                        'Values': [tgw_id]
                    }
                ]
            )
            tgw_details['peering_attachments'] = peering_attachments.get('TransitGatewayPeeringAttachments', [])
        except Exception as e:
            tgw_details['peering_attachments'] = {'Error': str(e)}
        
        return tgw_details
        
    except Exception as e:
        print(f"Error getting transit gateway details for {transit_gateway.get('TransitGatewayId', 'unknown')}: {str(e)}")
        return None

def process_route_tables_parallel(ec2_client, route_tables):
    """라우트 테이블별 상세 보안 정보를 병렬로 수집"""
    if not route_tables:
        return []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_route_table_security_details, ec2_client, rt) for rt in route_tables]
        results = []
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error processing route table: {str(e)}")
                continue
    
    return results

def get_route_table_security_details(ec2_client, route_table):
    """개별 라우트 테이블의 보안 상세 정보 수집"""
    try:
        route_table_id = route_table['TransitGatewayRouteTableId']
        rt_details = {
            'route_table_info': route_table,
            'associations': [],
            'propagations': [],
            'routes': []
        }
        
        # 1. 라우트 테이블 연결 상태 조회 (API 2)
        try:
            associations = ec2_client.get_transit_gateway_route_table_associations(
                TransitGatewayRouteTableId=route_table_id
            )
            rt_details['associations'] = associations.get('Associations', [])
        except Exception as e:
            rt_details['associations'] = {'Error': str(e)}
        
        # 2. 라우트 전파 설정 조회 (API 3)
        try:
            propagations = ec2_client.get_transit_gateway_route_table_propagations(
                TransitGatewayRouteTableId=route_table_id
            )
            rt_details['propagations'] = propagations.get('TransitGatewayRouteTablePropagations', [])
        except Exception as e:
            rt_details['propagations'] = {'Error': str(e)}
        
        # 3. 특정 라우트 검색 (API 4) - 모든 라우트 조회
        try:
            routes = ec2_client.search_transit_gateway_routes(
                TransitGatewayRouteTableId=route_table_id,
                Filters=[
                    {
                        'Name': 'state',
                        'Values': ['active', 'blackhole']
                    }
                ]
            )
            rt_details['routes'] = routes.get('Routes', [])
        except Exception as e:
            rt_details['routes'] = {'Error': str(e)}
        
        return rt_details
        
    except Exception as e:
        print(f"Error getting route table details for {route_table.get('TransitGatewayRouteTableId', 'unknown')}: {str(e)}")
        return None

def process_attachments_parallel(ec2_client, attachments):
    """연결별 상세 보안 정보를 병렬로 수집"""
    if not attachments:
        return []
    
    # 연결 타입별로 그룹핑
    vpc_attachments = [att for att in attachments if att.get('ResourceType') == 'vpc']
    peering_attachments = [att for att in attachments if att.get('ResourceType') == 'peering']
    other_attachments = [att for att in attachments if att.get('ResourceType') not in ['vpc', 'peering']]
    
    results = {
        'vpc_attachments_details': [],
        'peering_attachments_details': [],
        'other_attachments_details': []
    }
    
    # VPC 연결 상세 정보 수집
    if vpc_attachments:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(get_vpc_attachment_details, ec2_client, att) for att in vpc_attachments]
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results['vpc_attachments_details'].append(result)
                except Exception as e:
                    print(f"Error processing VPC attachment: {str(e)}")
                    continue
    
    # 피어링 연결 상세 정보 수집
    if peering_attachments:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(get_peering_attachment_details, ec2_client, att) for att in peering_attachments]
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results['peering_attachments_details'].append(result)
                except Exception as e:
                    print(f"Error processing peering attachment: {str(e)}")
                    continue
    
    # 기타 연결 정보
    results['other_attachments_details'] = other_attachments
    
    return results

def get_vpc_attachment_details(ec2_client, attachment):
    """VPC 연결의 상세 정보 수집"""
    try:
        attachment_id = attachment['TransitGatewayAttachmentId']
        
        # VPC 연결 상세 정보 조회 (이미 API 5에서 수집됨)
        vpc_attachment_details = {
            'attachment_info': attachment,
            'security_analysis': {
                'resource_type': attachment.get('ResourceType'),
                'state': attachment.get('State'),
                'creation_time': attachment.get('CreationTime'),
                'resource_owner_id': attachment.get('ResourceOwnerId'),
                'tags': attachment.get('Tags', [])
            }
        }
        
        return vpc_attachment_details
        
    except Exception as e:
        print(f"Error getting VPC attachment details for {attachment.get('TransitGatewayAttachmentId', 'unknown')}: {str(e)}")
        return None

def get_peering_attachment_details(ec2_client, attachment):
    """피어링 연결의 상세 정보 수집"""
    try:
        attachment_id = attachment['TransitGatewayAttachmentId']
        
        # 피어링 연결 상세 정보 조회 (이미 API 6에서 수집됨)
        peering_attachment_details = {
            'attachment_info': attachment,
            'security_analysis': {
                'resource_type': attachment.get('ResourceType'),
                'state': attachment.get('State'),
                'creation_time': attachment.get('CreationTime'),
                'resource_owner_id': attachment.get('ResourceOwnerId'),
                'cross_account_analysis': {
                    'is_cross_account': attachment.get('ResourceOwnerId') != attachment.get('TransitGatewayOwnerId'),
                    'resource_owner': attachment.get('ResourceOwnerId'),
                    'transit_gateway_owner': attachment.get('TransitGatewayOwnerId')
                },
                'tags': attachment.get('Tags', [])
            }
        }
        
        return peering_attachment_details
        
    except Exception as e:
        print(f"Error getting peering attachment details for {attachment.get('TransitGatewayAttachmentId', 'unknown')}: {str(e)}")
        return None

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
