import os
import aioboto3
from botocore.exceptions import ClientError
from loguru import logger

# S3/R2 Configuration
S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL")
S3_ACCESS_KEY_ID = os.getenv("S3_ACCESS_KEY_ID")
S3_SECRET_ACCESS_KEY = os.getenv("S3_SECRET_ACCESS_KEY")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "droidraksha")
S3_REGION_NAME = os.getenv("S3_REGION_NAME", "auto")

session = aioboto3.Session()

def is_s3_configured() -> bool:
    return all([S3_ENDPOINT_URL, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY])

def get_s3_client():
    return session.client(
        "s3",
        endpoint_url=S3_ENDPOINT_URL,
        aws_access_key_id=S3_ACCESS_KEY_ID,
        aws_secret_access_key=S3_SECRET_ACCESS_KEY,
        region_name=S3_REGION_NAME,
    )

async def upload_file(file_path: str, object_name: str) -> bool:
    """Upload a file to an S3/R2 bucket."""
    if not is_s3_configured():
        logger.warning(f"S3 not configured. Skipping upload for {object_name}")
        return False

    try:
        async with get_s3_client() as s3:
            await s3.upload_file(file_path, S3_BUCKET_NAME, object_name)
            logger.info(f"Successfully uploaded {object_name} to S3/R2")
            return True
    except ClientError as e:
        logger.error(f"Failed to upload {object_name} to S3: {e}")
        return False

async def upload_fileobj(file_obj, object_name: str) -> bool:
    """Upload a file-like object (e.g. BytesIO) to an S3/R2 bucket."""
    if not is_s3_configured():
        logger.warning(f"S3 not configured. Skipping upload_fileobj for {object_name}")
        return False

    try:
        async with get_s3_client() as s3:
            file_obj.seek(0)
            await s3.upload_fileobj(file_obj, S3_BUCKET_NAME, object_name)
            logger.info(f"Successfully uploaded {object_name} to S3/R2 from memory")
            return True
    except ClientError as e:
        logger.error(f"Failed to upload memory object {object_name} to S3: {e}")
        return False

async def download_file(object_name: str, file_path: str) -> bool:
    """Download a file from an S3/R2 bucket."""
    if not is_s3_configured():
        return False

    try:
        async with get_s3_client() as s3:
            await s3.download_file(S3_BUCKET_NAME, object_name, file_path)
            return True
    except ClientError as e:
        logger.error(f"Failed to download {object_name} from S3: {e}")
        return False

async def get_presigned_url(object_name: str, expiration=3600) -> str | None:
    """Generate a presigned URL for secure frontend downloading."""
    if not is_s3_configured():
        return None

    try:
        async with get_s3_client() as s3:
            url = await s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': S3_BUCKET_NAME, 'Key': object_name},
                ExpiresIn=expiration
            )
            return url
    except ClientError as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        return None
