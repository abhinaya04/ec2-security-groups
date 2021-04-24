import boto3
import json
from getpass import getpass

def fetch_security_groups(instance_id):
	security_group_list = []
	client = boto3.client('ec2')
	response = client.describe_instances(InstanceIds = [instance_id])['Reservations']
	for each_instance in response:
		for data in each_instance['Instances']:
			for security_group in data['NetworkInterfaces']:
				for sg_id in security_group['Groups']:
					security_group_list.append(sg_id['GroupId'])
	sg_list = convert_security_group_arn(security_group_list)
	return sg_list

def convert_security_group_arn(security_group_list):
	sg_arn_list = []
	for sg in security_group_list:
		sg_arn = "arn:aws:ec2:*:*:security-group/" + sg
		sg_arn_list.append(sg_arn)
	return sg_arn_list


def create_user(client,user_name, password):
	response = client.create_user(Path='/',UserName=user_name)
	print(response)
	if 'ResponseMetadata' in response:
		if create_login_profile(client,user_name,password):
			return True
	return False


def create_login_profile(client,user_name,user_password):
	response = client.create_login_profile(UserName=user_name,Password=user_password,PasswordResetRequired=True)
	if response['ResponseMetadata']:
		return True
	return False


def convert_to_string(sg_list):
	sg_string = ' '.join(map(str, sg_list))
	joined_string = "\",\"".join(sg_string.split())
	return joined_string

def attach_change_password_policy(client,username):
	response = client.attach_user_policy(UserName=username,PolicyArn='arn:aws:iam::aws:policy/IAMUserChangePassword')
	if response['ResponseMetadata']:
		return True
	return False


if __name__ == "__main__":
	iam_client = boto3.client('iam')
	user_name = input("Please enter UserName to be created:\n")
	instance_id = input("Please enter the instance_id:\n")
	password = input("Please enter the password:\n")
	if create_user(iam_client, user_name,password):
		print("The User {} has been created successfully".format(user_name))
	sg_list = fetch_security_groups(instance_id)
	sg_string = convert_to_string(sg_list)
	policy_doc = """{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"},
					{"Effect":"Allow","Action":["ec2:StartInstances","ec2:StopInstances","ec2:RebootInstances","ec2:Update*"],"Resource":"arn:aws:ec2:ap-southeast-1:*:instance/instance-id"},
					{"Effect": "Allow","Action": ["ec2:AuthorizeSecurityGroupEgress","ec2:AuthorizeSecurityGroupIngress","ec2:DeleteSecurityGroup","ec2:RevokeSecurityGroupEgress","ec2:RevokeSecurityGroupIngress"],"Resource": ["sg_string"]},
					{"Action": ["ec2:DescribeSecurityGroups","ec2:DescribeSecurityGroupReferences","ec2:DescribeStaleSecurityGroups","ec2:DescribeVpcs"],"Effect": "Allow","Resource": ["sg_string"]}]}"""
	updated_policy_doc = policy_doc.replace('instance-id',instance_id)
	final_policy_doc = updated_policy_doc.replace('sg_string',sg_string)
	print("Attching the Change Password policy")
	if attach_change_password_policy(iam_client,user_name):
		print("The Change Password Policy has been attached")
	else:
		print("The Change Password Policy attachment is not successful")
	print("Attaching the EC2 Restrict Policy to the User")
	response = iam_client.put_user_policy(PolicyDocument= final_policy_doc,PolicyName='EC2RestrictPolicy',UserName=user_name)
	print(response)
	if response['ResponseMetadata']:
		print("The EC2 Restriction Policy has been applied successfully")
	else:
		print("The policy attachment is not successful")