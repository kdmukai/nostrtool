# Deploying to AWS Lambda

## AWS config
Create an IAM user for zappa.

Grant it:
* AmazonS3FullAccess
* APIGatewayAdministrator
* AWSLambdaFullAccess
* AWSCloudFormationFullAccess
* CloudFrontFullAccess
* CloudWatchEventsFullAccess
* IAMFullAccess
* AmazonRoute53DomainsReadOnlyAccess

Generate access keys and store them in your local ~/.aws/credentials

## Build the Lambda image
Must do this in an `amd64` Docker image!

## configure zappa
_Note: Do everything in Zappa from within the `src` dir._
```
cd src
zappa init
```

Add `aws_region` to the resulting zappa_settings.json

