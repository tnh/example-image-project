from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer
from aws_lambda_powertools import Metrics
from aws_lambda_powertools.metrics import MetricUnit
from datetime import datetime, timedelta
import boto3
import os
from datetime import timedelta
import random
import string
import json
from urllib.parse import urlencode
from io import BytesIO
from PIL import Image


app = APIGatewayRestResolver()
tracer = Tracer()
logger = Logger()
metrics = Metrics(namespace="ImageProject")
dynamodb = boto3.resource('dynamodb')

def generate_random_string(length=20):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

def get_user_id_from_event(event):
    return "abc124"

    #once cognito is switched on
    if 'requestContext' in event and 'authorizer' in event['requestContext']:
        claims = event['requestContext']['authorizer'].get('claims', {})
        return claims.get('sub')  # 'sub' is the user's unique identifier in Cognito
    return None

@app.get("/hello")
@tracer.capture_method
def hello():
    metrics.add_metric(name="HelloWorldInvocations", unit=MetricUnit.Count, value=1)
    logger.info("Hello world API - HTTP 200")
    return {"message": "hello world"}

@app.post("/login")
@tracer.capture_method
def login():
    metrics.add_metric(name="LoginAttempts", unit=MetricUnit.Count, value=1)
    logger.info("Login API - HTTP 200")
    
    cognito_domain = os.environ['COGNITO_DOMAIN']
    login_url = f"{cognito_domain}/login?client_id="
    
    return {"statusCode": 302, "headers": {"Location": login_url}}   


@app.get("/list")
@tracer.capture_method
def list_items():
    metrics.add_metric(name="ListRequests", unit=MetricUnit.Count, value=1)
    logger.info("List API - HTTP 200")

    # Add your list logic here
    user_id = get_user_id_from_event(app.current_event.raw_event)
    if not user_id:
        return {"statusCode": 401, "body": "Unauthorized"}

    table = dynamodb.Table(os.environ['IMAGE_TABLE_NAME'])

    # Get pagination parameters from query string
    query_params = app.current_event.query_string_parameters or {}
    limit = int(query_params.get('limit', 10))
    last_evaluated_key = query_params.get('lastEvaluatedKey')

    try:
        # Build query parameters
        query_kwargs = {
            'KeyConditionExpression': boto3.dynamodb.conditions.Key('user_id').eq(user_id),
            'Limit': limit
        }
        if last_evaluated_key:
            query_kwargs['ExclusiveStartKey'] = json.loads(last_evaluated_key)

        # Query the table with pagination
        response = table.query(**query_kwargs)

        items = response.get('Items', [])
        last_evaluated_key = response.get('LastEvaluatedKey')

        # Process items to include only relevant information
        processed_items = []
        for item in items:
            processed_item = {
                'object_name': item['object_name'],
                'timestamp': item['timestamp']
            }
            if 'resized_key' in item:
                processed_item['resized_key'] = item['resized_key']
            processed_items.append(processed_item)

        body = {
            "items": processed_items,
            "count": len(processed_items)
        }

        # Generate next link if there is more data to fetch
        if last_evaluated_key:
            query_params = {
                'limit': limit,
                'lastEvaluatedKey': json.dumps(last_evaluated_key)
            }
            next_link = f"/list?{urlencode(query_params)}"
            body['next'] = next_link

        return {
            "statusCode": 200,
            "body": json.dumps(body)
        }

    except Exception as e:
        logger.error(f"Error listing items: {str(e)}")
        return {"statusCode": 500, "body": "Error listing items"}


@app.get("/shorten/<url>")
@tracer.capture_method
def shorten_url(url):
    metrics.add_metric(name="ShortenRequests", unit=MetricUnit.Count, value=1)
    logger.info("Shorten API - HTTP 200")
    table = dynamodb.Table(os.environ['SHORTENER_TABLE_NAME'])
    current_time = datetime.now()
    expiration_time = current_time + timedelta(days=30)
    expiration_timestamp = int(expiration_time.timestamp())
    # Add your URL shortening logic here
    try:
        short_id = generate_random_string(6)
        table.put_item(
            Item={
                'short_id': short_id,
                'original_url': url,
                'expiration_time': expiration_timestamp
            }
        )
        short_url = f"https://{app.current_event.headers['Host']}/r/{short_id}"
        return {"statusCode": 200, "body": {"short_url": short_url}}
    except Exception as e:
        logger.error(f"Error creating short URL: {str(e)}")
        return {"statusCode": 500, "body": "Error creating short URL"}


@app.get("/r/<short_id>")
@tracer.capture_method
def redirect_to_original_url(short_id):
    table = dynamodb.Table(os.environ['SHORTENER_TABLE_NAME'])
    try:
        response = table.get_item(Key={'short_id': short_id})
        item = response.get('Item')
        if item:
            original_url = item['original_url']
            return {"statusCode": 302, "headers": {"Location": original_url}}
        else:
            return {"statusCode": 404, "body": "Short URL not found"}
    except Exception as e:
        logger.error(f"Error retrieving original URL: {str(e)}")
        return {"statusCode": 500, "body": "Error retrieving original URL"}
    
@app.get("/upload/<object_name>")
@tracer.capture_method
def upload(object_name):
    metrics.add_metric(name="UploadRequests", unit=MetricUnit.Count, value=1)
    logger.info("Upload API - HTTP 200")
    s3_client = boto3.client('s3')
    bucket_name = os.environ['BUCKET_NAME']
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['IMAGE_TABLE_NAME'])

    timestamp = datetime.now().isoformat()
    #user_id = generate_random_string(20)
    user_id = get_user_id_from_event(app.current_event.raw_event)
    object_key = f"{user_id}/{object_name}"

    try:
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': bucket_name,
                'Key': object_key
            },
            ExpiresIn=int(os.environ.get('PRESIGNED_URL_TIMEOUT', 300))
        )

        item = {
            'user_id': user_id,
            'object_name': object_key,
            'timestamp': timestamp
        }
        table.put_item(Item=item)

        return {"message": presigned_url}
    except Exception as e:
        logger.error(f"Error generating presigned URL: {e}")
        return {"error": "Failed to generate presigned URL"}

@tracer.capture_method
def process_s3_event(event: dict) -> dict:
    metrics.add_metric(name="S3Uploads", unit=MetricUnit.Count, value=1)
    logger.info("S3 Upload Event - Processing")

    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        try:
            # Download the image from S3
            response = s3_client.get_object(Bucket=bucket, Key=key)
            image_content = response['Body'].read()

            # Open the image using Pillow
            with Image.open(BytesIO(image_content)) as img:
                # Resize the image
                img.thumbnail((int(os.environ['RESIZE_WIDTH']), int(os.environ['RESIZE_HEIGHT'])))
                
                # Save the resized image to a BytesIO object
                buffer = BytesIO()
                img.save(buffer, format=img.format)
                buffer.seek(0)

                # Upload the resized image back to S3
                resized_key = f"resized/{key}"
                s3_client.put_object(Bucket=bucket, Key=resized_key, Body=buffer)

            logger.info(f"Successfully resized and uploaded image: {key}")

            # Update DynamoDB
            table = dynamodb.Table(os.environ['IMAGE_TABLE_NAME'])
            table.update_item(
                Key={'user_id': key.split('/')[0], 'object_name': key},
                UpdateExpression="SET resized_key = :resized_key",
                ExpressionAttributeValues={':resized_key': resized_key}
            )

        except Exception as e:
            logger.error(f"Error processing image {key}: {str(e)}")

    return {"message": "S3 upload processed"}

        
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
@tracer.capture_lambda_handler
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    if 'Records' in event and 'eventSource' in event['Records'][0] and event['Records'][0]['eventSource'] == 'aws:s3':
        return process_s3_event(event)
    else:
        return app.resolve(event, context)
