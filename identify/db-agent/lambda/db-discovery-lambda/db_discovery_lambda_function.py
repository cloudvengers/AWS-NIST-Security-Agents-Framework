import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    DB-AGENT Database Resources Discovery Lambda 함수
    데이터베이스 리소스 (RDS, DynamoDB, DAX, DynamoDB Streams) 존재 여부 확인
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
        
        # 데이터베이스 리소스 발견
        discovery_results = discover_database_resources_parallel(session, target_region, current_time)
        
        # 응답 데이터 구성
        total_services_with_resources = sum(1 for service in discovery_results.values() if service.get('has_resources', False))
        
        response_data = {
            'function': 'discoverDatabaseResources',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'discovery_timestamp': context.aws_request_id,
            'services_discovered': discovery_results,
            'collection_summary': {
                'total_services_checked': len(discovery_results),
                'services_with_resources': total_services_with_resources,
                'discovery_method': 'parallel_processing',
                'agent_type': 'db-agent',
                'focus': 'database_resource_security_identification_rds_dynamodb_dax_streams'
            }
        }
        
        return create_bedrock_success_response(event, response_data)
        
    except Exception as e:
        error_message = f"데이터베이스 리소스 Discovery 과정에서 오류 발생: {str(e)}"
        print(f"Error in db-agent discovery lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def discover_database_resources_parallel(session, target_region, current_time):
    """
    데이터베이스 리소스 (RDS + DynamoDB + DAX + DynamoDB Streams) 병렬 발견
    """
    services_to_check = [
        ('rds', discover_rds_resources),
        ('dynamodb', discover_dynamodb_resources),
        ('dax', discover_dax_resources),
        ('dynamodb_streams', discover_dynamodb_streams_resources)
    ]
    
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_service = {
            executor.submit(discover_func, session, target_region, current_time): service_name 
            for service_name, discover_func in services_to_check
        }
        
        for future in concurrent.futures.as_completed(future_to_service):
            service_name = future_to_service[future]
            try:
                result = future.result()
                results[service_name] = result
            except Exception as e:
                print(f"Error discovering {service_name}: {str(e)}")
                results[service_name] = {
                    'has_resources': False,
                    'resource_count': 0,
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return results

def discover_rds_resources(session, target_region, current_time):
    """RDS 데이터베이스 리소스 발견 - 기본적인 존재 여부만 확인"""
    try:
        rds_client = session.client('rds', region_name=target_region)
        
        # RDS 인스턴스 목록 조회
        instances_response = rds_client.describe_db_instances()
        instances = instances_response.get('DBInstances', [])
        
        if not instances:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['db_instances'],
                'status': 'no_resources',
                'details': {
                    'note': 'RDS 데이터베이스 인스턴스가 존재하지 않습니다.'
                }
            }
        
        return {
            'has_resources': len(instances) > 0,
            'resource_count': len(instances),
            'resource_types': ['db_instances'],
            'status': 'active',
            'details': {
                'total_instances': len(instances),
                'sample_instance_ids': [i['DBInstanceIdentifier'] for i in instances[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering RDS resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_dynamodb_resources(session, target_region, current_time):
    """DynamoDB 테이블 리소스 발견 - 기본적인 존재 여부만 확인"""
    try:
        dynamodb_client = session.client('dynamodb', region_name=target_region)
        
        # DynamoDB 테이블 목록 조회
        tables_response = dynamodb_client.list_tables()
        table_names = tables_response.get('TableNames', [])
        
        if not table_names:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['tables'],
                'status': 'no_tables',
                'details': {
                    'note': 'DynamoDB 테이블이 존재하지 않습니다.'
                }
            }
        
        return {
            'has_resources': len(table_names) > 0,
            'resource_count': len(table_names),
            'resource_types': ['tables'],
            'status': 'active',
            'details': {
                'total_tables': len(table_names),
                'sample_table_names': table_names[:5],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering DynamoDB resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_dax_resources(session, target_region, current_time):
    """DynamoDB Accelerator (DAX) 클러스터 리소스 발견 - 기본적인 존재 여부만 확인"""
    try:
        dax_client = session.client('dax', region_name=target_region)
        
        # DAX 클러스터 목록 조회
        clusters_response = dax_client.describe_clusters()
        clusters = clusters_response.get('Clusters', [])
        
        if not clusters:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['dax_clusters'],
                'status': 'no_clusters',
                'details': {
                    'note': 'DAX 클러스터가 존재하지 않습니다.'
                }
            }
        
        return {
            'has_resources': len(clusters) > 0,
            'resource_count': len(clusters),
            'resource_types': ['dax_clusters'],
            'status': 'active',
            'details': {
                'total_clusters': len(clusters),
                'sample_cluster_names': [c['ClusterName'] for c in clusters[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering DAX resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

def discover_dynamodb_streams_resources(session, target_region, current_time):
    """DynamoDB Streams 리소스 발견 - 기본적인 존재 여부만 확인"""
    try:
        streams_client = session.client('dynamodbstreams', region_name=target_region)
        
        # DynamoDB Streams 목록 조회
        streams_response = streams_client.list_streams()
        streams = streams_response.get('Streams', [])
        
        if not streams:
            return {
                'has_resources': False,
                'resource_count': 0,
                'resource_types': ['streams'],
                'status': 'no_streams',
                'details': {
                    'note': 'DynamoDB Streams가 존재하지 않습니다.'
                }
            }
        
        return {
            'has_resources': len(streams) > 0,
            'resource_count': len(streams),
            'resource_types': ['streams'],
            'status': 'active',
            'details': {
                'total_streams': len(streams),
                'sample_stream_arns': [s['StreamArn'] for s in streams[:5]],
                'target_region': target_region
            }
        }
        
    except Exception as e:
        print(f"Error discovering DynamoDB Streams resources: {str(e)}")
        return {
            'has_resources': False,
            'resource_count': 0,
            'status': 'error',
            'error_message': str(e)
        }

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
        'function': event.get('function', 'discoverDatabaseResources'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'db-discovery'),
        'function': event.get('function', 'discoverDatabaseResources'),
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
