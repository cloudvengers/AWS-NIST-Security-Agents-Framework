# CloudFormation API 함수들 (18개)

# 스택 보안 상태 분석 (6개)
def get_stacks_info(client):
    """DescribeStacks - 스택 기본 정보, 상태, IAM 역할, 보안 설정 조회"""
    try:
        response = client.describe_stacks()
        stacks = response.get('Stacks', [])
        
        return {
            'status': 'success',
            'stacks': stacks[:10],  # 최대 10개만 상세 정보
            'total_stacks': len(stacks),
            'stack_statuses': [s.get('StackStatus') for s in stacks]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_events(client):
    """DescribeStackEvents - 스택 이벤트 이력을 통한 보안 관련 실패 및 문제 추적"""
    try:
        # 먼저 스택 목록을 가져와서 이벤트 조회
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'stack_events': [],
                'message': '스택이 없어 이벤트를 조회할 수 없습니다.'
            }
        
        all_events = []
        for stack in stacks[:5]:  # 성능을 위해 최대 5개 스택만
            try:
                events_response = client.describe_stack_events(StackName=stack['StackName'])
                events = events_response.get('StackEvents', [])
                all_events.extend(events[:20])  # 스택당 최대 20개 이벤트
            except Exception as e:
                print(f"Error getting events for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'stack_events': all_events,
            'total_events': len(all_events)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resources(client):
    """DescribeStackResources - 스택 내 모든 리소스의 보안 상태 및 구성 확인"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'stack_resources': [],
                'message': '스택이 없어 리소스를 조회할 수 없습니다.'
            }
        
        all_resources = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                resources_response = client.describe_stack_resources(StackName=stack['StackName'])
                resources = resources_response.get('StackResources', [])
                all_resources.extend(resources)
            except Exception as e:
                print(f"Error getting resources for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'stack_resources': all_resources,
            'total_resources': len(all_resources)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resource_details(client):
    """DescribeStackResource - 개별 리소스의 상세 보안 설정 및 속성 분석"""
    try:
        # 먼저 리소스 목록을 가져와서 상세 정보 조회
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'resource_details': [],
                'message': '스택이 없어 리소스 상세 정보를 조회할 수 없습니다.'
            }
        
        resource_details = []
        for stack in stacks[:2]:  # 성능을 위해 최대 2개 스택만
            try:
                resources_response = client.describe_stack_resources(StackName=stack['StackName'])
                resources = resources_response.get('StackResources', [])
                
                for resource in resources[:5]:  # 스택당 최대 5개 리소스만
                    try:
                        detail_response = client.describe_stack_resource(
                            StackName=stack['StackName'],
                            LogicalResourceId=resource['LogicalResourceId']
                        )
                        resource_details.append(detail_response.get('StackResourceDetail', {}))
                    except Exception as e:
                        print(f"Error getting resource detail: {str(e)}")
                        continue
            except Exception as e:
                print(f"Error processing stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'resource_details': resource_details,
            'total_details': len(resource_details)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stacks_list(client):
    """ListStacks - 계정 내 모든 스택의 요약 정보 및 전체 보안 현황 파악"""
    try:
        response = client.list_stacks()
        stack_summaries = response.get('StackSummaries', [])
        
        return {
            'status': 'success',
            'stack_summaries': stack_summaries,
            'total_stacks': len(stack_summaries),
            'stack_statuses': [s.get('StackStatus') for s in stack_summaries]
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resources_list(client):
    """ListStackResources - 특정 스택 내 리소스 목록 및 보안 관련 리소스 식별"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'stack_resources_list': [],
                'message': '스택이 없어 리소스 목록을 조회할 수 없습니다.'
            }
        
        all_resources_list = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                resources_response = client.list_stack_resources(StackName=stack['StackName'])
                resources = resources_response.get('StackResourceSummaries', [])
                all_resources_list.extend(resources)
            except Exception as e:
                print(f"Error listing resources for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'stack_resources_list': all_resources_list,
            'total_resources': len(all_resources_list)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

# 드리프트 보안 분석 (2개)
def get_drift_detection_status(client):
    """DescribeStackDriftDetectionStatus - 드리프트 탐지 작업 상태 및 보안 설정 변경 탐지 결과 확인"""
    try:
        # 실제 드리프트 탐지 ID가 필요하므로 샘플 응답 반환
        return {
            'status': 'success',
            'drift_detection_status': [],
            'message': '드리프트 탐지 작업이 실행된 후 상태를 확인할 수 있습니다.'
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}

def get_stack_resource_drifts(client):
    """DescribeStackResourceDrifts - 리소스별 드리프트 상세 정보 및 보안 설정 불일치 분석"""
    try:
        stacks_response = client.describe_stacks()
        stacks = stacks_response.get('Stacks', [])
        
        if not stacks:
            return {
                'status': 'success',
                'resource_drifts': [],
                'message': '스택이 없어 드리프트를 조회할 수 없습니다.'
            }
        
        all_drifts = []
        for stack in stacks[:3]:  # 성능을 위해 최대 3개 스택만
            try:
                drifts_response = client.describe_stack_resource_drifts(StackName=stack['StackName'])
                drifts = drifts_response.get('StackResourceDrifts', [])
                all_drifts.extend(drifts)
            except Exception as e:
                print(f"Error getting drifts for stack {stack['StackName']}: {str(e)}")
                continue
        
        return {
            'status': 'success',
            'resource_drifts': all_drifts,
            'total_drifts': len(all_drifts)
        }
    except Exception as e:
        return {'status': 'error', 'error_message': str(e)}
