import json, os, boto3

def lambda_handler(event, context):
   if 'detail' not in event or ('detail' in event and 'eventName' not in event['detail']):
        return {"Result": "Failure", "Message": "Lambda not triggered by an event"}
    
    if(event['detail']['eventName'] == 'AuthorizeSecurityGroupIngress'):
        security_group_id = event['detail']['requestParameters']['groupId']
        result = revoke_security_group_ingress(event['detail'])
        message = "AUTO-MITIGATED: Ingress rule removed from security group: {} that was added by {}: {}".format(result['group_id'],result['user_name'],json.dumps(result['ip_permissions']))
        boto3.client('sns').publish( TargetArn = os.environ['sns_topic_arn'], Message = message, Subject = "Auto-mitigation successful" )
        
def revoke_security_group_ingress(event_detail):
    request_parameters = event_detail['requestParameters']
    ip_permissions = normalize_paramter_names(request_parameters['ipPermissions']['items'])
    print(ip_permissions)
    for each_item in ip_permissions:
        if each_item['FromPort'] not in os.environ['allowed_ports'].split(',') and each_item['ToPort'] not in os.environ['allowed_ports'].split(',') :
            for cidr_ip in each_item['IpRanges']:
                print(cidr_ip)
                if cidr_ip['CidrIp'] in os.environ['unauthorized_source']:
                    response = boto3.client('ec2').revoke_security_group_ingress(GroupId=request_parameters['groupId'],IpPermissions=ip_permissions)
                    result = {}
                    result['group_id'] = request_parameters['groupId']
                    result['user_name'] = event_detail['userIdentity']['arn']
                    result['ip_permissions'] = ip_permissions
                    return result
          
        
def normalize_paramter_names(ip_items):
    new_ip_items = []
    for ip_item in ip_items:
        new_ip_item = {
            "IpProtocol": ip_item['ipProtocol'],
            "FromPort": ip_item['fromPort'],
            "ToPort": ip_item['toPort']
        }
        # CidrIp or CidrIpv6 (IPv4 or IPv6)?
        if 'ipv6Ranges' in ip_item and ip_item['ipv6Ranges']:
            # This is an IPv6 permission range, so change the key names.
            ipv_range_list_name = 'ipv6Ranges'
            ipv_address_value = 'cidrIpv6'
            ipv_range_list_name_capitalized = 'Ipv6Ranges'
            ipv_address_value_capitalized = 'CidrIpv6'
        else:
            ipv_range_list_name = 'ipRanges'
            ipv_address_value = 'cidrIp'
            ipv_range_list_name_capitalized = 'IpRanges'
            ipv_address_value_capitalized = 'CidrIp'

        ip_ranges = []
        # Next, build the IP permission list.
        for item in ip_item[ipv_range_list_name]['items']:
            ip_ranges.append(
                {ipv_address_value_capitalized: item[ipv_address_value]}
            )
        new_ip_item[ipv_range_list_name_capitalized] = ip_ranges
        new_ip_items.append(new_ip_item)
    return new_ip_items