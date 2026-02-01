import json
import boto3
import concurrent.futures
from botocore.exceptions import ClientError
from datetime import datetime

def lambda_handler(event, context):
    """
    DETECT-AGENT-02 Detective Lambda 함수
    Amazon Detective 보안 이벤트 상관 분석 및 조사 그래프 분석
    """
    try:
        # 파라미터 추출 및 검증
        parameters = event.get('parameters', [])
        param_dict = {param['name']: param['value'] for param in parameters}
        target_region = param_dict.get('target_region', 'us-east-1')
        
        # 세션 속성에서 고객 자격증명 획득
        session_attributes = event.get('sessionAttributes', {})
        access_key = session_attributes.get('access_key')
        secret_key = session_attributes.get('secret_key')
        current_time = session_attributes.get('current_time', datetime.utcnow().isoformat())
        
        if not access_key or not secret_key:
            return create_bedrock_error_response(event, "고객 자격증명이 제공되지 않았습니다. 세션을 다시 시작해주세요.")
        
        # 고객 자격증명으로 AWS 클라이언트 생성
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=target_region
        )
        detective_client = session.client('detective', region_name=target_region)
        
        # Detective 원시 데이터 병렬 수집
        raw_data = collect_detective_raw_data_parallel(detective_client, target_region, current_time)
        
        return create_bedrock_success_response(event, raw_data)
        
    except Exception as e:
        error_message = f"Detective 보안 분석 중 오류 발생: {str(e)}"
        print(f"Error in detective lambda: {error_message}")
        return create_bedrock_error_response(event, error_message)

def collect_detective_raw_data_parallel(client, target_region, current_time):
    """
    Detective 원시 데이터를 병렬로 수집
    """
    # 1단계: 그래프 목록 조회 (기본 정보)
    try:
        graphs_response = client.list_graphs()
        graphs = graphs_response.get('GraphList', [])
        
        if not graphs:
            return {
                'function': 'analyzeDetectiveSecurity',
                'target_region': target_region,
                'collection_timestamp': current_time,
                'analysis_time': current_time,
                'status': 'no_graphs',
                'message': 'Detective 행동 그래프가 존재하지 않습니다.',
                'collection_summary': {
                    'graphs_found': 0,
                    'total_apis_called': 1,
                    'processing_method': 'parallel_processing'
                }
            }
        
        # 2단계: 각 그래프에 대해 병렬로 상세 정보 수집
        all_graph_data = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_graph = {
                executor.submit(process_graph_parallel, client, graph): graph 
                for graph in graphs
            }
            
            for future in concurrent.futures.as_completed(future_to_graph):
                graph = future_to_graph[future]
                try:
                    graph_data = future.result()
                    if graph_data:
                        all_graph_data.append(graph_data)
                except Exception as e:
                    print(f"Error processing graph {graph.get('Arn', 'unknown')}: {str(e)}")
                    # 개별 그래프 오류는 전체 수집에 영향 없도록 계속 진행
                    continue
        
        # 응답 데이터 구성
        response_data = {
            'function': 'analyzeDetectiveSecurity',
            'target_region': target_region,
            'collection_timestamp': current_time,
            'analysis_time': current_time,
            'graphs_data': all_graph_data,
            'collection_summary': {
                'total_graphs': len(graphs),
                'processed_graphs': len(all_graph_data),
                'total_apis_called': calculate_total_apis_called(all_graph_data),
                'processing_method': 'parallel_processing',
                'collection_timestamp': context.aws_request_id if 'context' in locals() else 'unknown'
            }
        }
        
        return response_data
        
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
            return {
                'function': 'analyzeDetectiveSecurity',
                'target_region': target_region,
                'collection_timestamp': current_time,
                'analysis_time': current_time,
                'status': 'access_denied',
                'error_message': 'Detective 서비스 접근 권한이 없습니다.',
                'collection_summary': {
                    'graphs_found': 0,
                    'total_apis_called': 1,
                    'processing_method': 'error_handling'
                }
            }
        raise

def process_graph_parallel(client, graph):
    """
    개별 그래프에 대한 모든 정보를 병렬로 수집
    """
    graph_arn = graph.get('Arn')
    if not graph_arn:
        return None
    
    # 그래프별 수집할 데이터 정의
    data_collection_tasks = [
        ('datasource_packages', lambda: get_datasource_packages(client, graph_arn)),
        ('membership_datasources', lambda: get_membership_datasources(client, graph_arn)),
        ('investigations', lambda: get_investigations(client, graph_arn)),
        ('resource_tags', lambda: get_resource_tags(client, graph_arn))
    ]
    
    graph_data = {
        'graph_arn': graph_arn,
        'graph_created_time': graph.get('CreatedTime'),
        'graph_status': 'ACTIVE'  # ListGraphs에서 반환되는 그래프는 활성 상태
    }
    
    # 병렬로 데이터 수집
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_task = {
            executor.submit(task_func): task_name 
            for task_name, task_func in data_collection_tasks
        }
        
        for future in concurrent.futures.as_completed(future_to_task):
            task_name = future_to_task[future]
            try:
                result = future.result()
                graph_data[task_name] = result
            except Exception as e:
                print(f"Error in {task_name} for graph {graph_arn}: {str(e)}")
                graph_data[task_name] = {
                    'status': 'error',
                    'error_message': str(e)
                }
    
    return graph_data

def get_datasource_packages(client, graph_arn):
    """
    데이터소스 패키지 목록 조회
    """
    try:
        response = client.list_datasource_packages(GraphArn=graph_arn)
        return {
            'status': 'success',
            'datasource_packages': response.get('DatasourcePackages', {}),
            'next_token': response.get('NextToken')
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return {
                'status': 'not_found',
                'message': '데이터소스 패키지를 찾을 수 없습니다.'
            }
        raise

def get_membership_datasources(client, graph_arn):
    """
    멤버십 데이터소스 기록 조회
    """
    try:
        response = client.batch_get_membership_datasources(GraphArns=[graph_arn])
        return {
            'status': 'success',
            'membership_datasources': response.get('MembershipDatasources', []),
            'unprocessed_graphs': response.get('UnprocessedGraphs', [])
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return {
                'status': 'not_found',
                'message': '멤버십 데이터소스 정보를 찾을 수 없습니다.'
            }
        raise

def get_investigations(client, graph_arn):
    """
    조사 목록 및 상세 정보 조회
    """
    try:
        # 조사 목록 조회
        investigations_response = client.list_investigations(
            GraphArn=graph_arn,
            MaxResults=50  # 성능을 위해 제한
        )
        
        investigations = investigations_response.get('InvestigationDetails', [])
        
        if not investigations:
            return {
                'status': 'success',
                'investigations_count': 0,
                'investigations': [],
                'message': '진행 중인 조사가 없습니다.'
            }
        
        # 각 조사에 대한 상세 정보 및 지표 병렬 수집
        detailed_investigations = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_investigation = {
                executor.submit(get_investigation_details, client, graph_arn, inv['InvestigationId']): inv 
                for inv in investigations[:10]  # 성능을 위해 최대 10개로 제한
            }
            
            for future in concurrent.futures.as_completed(future_to_investigation):
                investigation = future_to_investigation[future]
                try:
                    detailed_info = future.result()
                    investigation_data = {
                        'basic_info': investigation,
                        'detailed_info': detailed_info
                    }
                    detailed_investigations.append(investigation_data)
                except Exception as e:
                    print(f"Error getting details for investigation {investigation.get('InvestigationId', 'unknown')}: {str(e)}")
                    detailed_investigations.append({
                        'basic_info': investigation,
                        'detailed_info': {
                            'status': 'error',
                            'error_message': str(e)
                        }
                    })
        
        return {
            'status': 'success',
            'investigations_count': len(investigations),
            'detailed_investigations': detailed_investigations,
            'next_token': investigations_response.get('NextToken')
        }
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return {
                'status': 'not_found',
                'message': '조사 정보를 찾을 수 없습니다.'
            }
        raise

def get_investigation_details(client, graph_arn, investigation_id):
    """
    특정 조사의 상세 정보 및 지표 조회
    """
    details = {}
    
    try:
        # 조사 상세 정보 조회
        investigation_response = client.get_investigation(
            GraphArn=graph_arn,
            InvestigationId=investigation_id
        )
        details['investigation_details'] = investigation_response
        
        # 지표 목록 조회
        indicators_response = client.list_indicators(
            GraphArn=graph_arn,
            InvestigationId=investigation_id,
            MaxResults=20  # 성능을 위해 제한
        )
        details['indicators'] = indicators_response.get('Indicators', [])
        details['indicators_next_token'] = indicators_response.get('NextToken')
        
    except Exception as e:
        details['error'] = str(e)
    
    return details

def get_resource_tags(client, graph_arn):
    """
    리소스 태그 조회
    """
    try:
        response = client.list_tags_for_resource(ResourceArn=graph_arn)
        return {
            'status': 'success',
            'tags': response.get('Tags', {})
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return {
                'status': 'not_found',
                'message': '리소스 태그를 찾을 수 없습니다.'
            }
        raise

def calculate_total_apis_called(graph_data_list):
    """
    호출된 총 API 개수 계산
    """
    base_apis = 1  # list_graphs
    per_graph_apis = 4  # datasource_packages, membership_datasources, investigations, resource_tags
    
    total_investigations = 0
    for graph_data in graph_data_list:
        investigations = graph_data.get('investigations', {})
        if investigations.get('status') == 'success':
            total_investigations += len(investigations.get('detailed_investigations', []))
    
    investigation_apis = total_investigations * 2  # get_investigation + list_indicators per investigation
    
    return base_apis + (len(graph_data_list) * per_graph_apis) + investigation_apis

def create_bedrock_success_response(event, response_data):
    """
    Bedrock Agent 성공 응답 생성
    """
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
    """
    Bedrock Agent 에러 응답 생성
    """
    error_data = {
        'function': event.get('function', 'analyzeDetectiveSecurity'),
        'status': 'error',
        'error_message': error_message
    }
    
    response_body = {
        'TEXT': {
            'body': json.dumps(error_data, ensure_ascii=False, indent=2)
        }
    }
    
    function_response = {
        'actionGroup': event.get('actionGroup', 'detective-security-analysis'),
        'function': event.get('function', 'analyzeDetectiveSecurity'),
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
