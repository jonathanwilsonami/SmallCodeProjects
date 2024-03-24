import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from awsglue.context import GlueContext
from awsglue.job import Job

from pyspark.sql.functions import split, col
from pyspark.context import SparkContext
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType, IntegerType

## @params: [JOB_NAME]
args = getResolvedOptions(sys.argv, ['JOB_NAME'])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

path_pattern = "s3://iot23-project/opt/Malware-Project/BigDataset/IoTScenarios/*/bro/conn.log.labeled"

df = spark.read.option("header", "true") \
    .option("sep", "\t") \
    .option("comment", "#") \
    .csv(path_pattern)

# The last 3 cols did not have \t so this is a fix for that
last_col = df.columns[-1]
split_col = F.split(df[last_col], '\s+')
df = df.withColumn("tunnel_parents", split_col.getItem(0))
df = df.withColumn("label", split_col.getItem(1))
df = df.withColumn("detailed-label", split_col.getItem(2))
df = df.drop(last_col)

headers = ["timestamp", "connection_uid", "source_ip", "source_port", "destination_ip", "destination_port", "conn_proto", "app_proto_service", "conn_duration",
                       "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "conn_history", 
                       "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents", "label", "malware_name"]

iot23 = df.toDF(*headers)

# Data Cleaning and Transformations
# --------------------------------------------

# Capitalize benign 
iot23 = iot23.withColumn("label", F.when(F.col("label") == "benign", "Benign").otherwise(F.col("label")))

# Replace null values with Benign as "-" values are all Benign
iot23 = iot23.withColumn("malware_name", F.when(F.col("malware_name") == "-", "Benign").otherwise(F.col("malware_name")))

# Don't need these for analysis 
iot23 = iot23.drop("local_orig", "local_resp", "tunnel_parents")

# Type Casting 
iot23 = iot23.withColumn("orig_bytes", F.col("orig_bytes").cast(DoubleType()))
iot23 = iot23.withColumn("resp_bytes", F.col("resp_bytes").cast(DoubleType()))
iot23 = iot23.withColumn("orig_ip_bytes", F.col("orig_ip_bytes").cast(DoubleType()))
iot23 = iot23.withColumn("resp_ip_bytes", F.col("resp_ip_bytes").cast(DoubleType()))

iot23 = iot23.withColumn("orig_pkts", F.col("orig_pkts").cast(IntegerType()))
iot23 = iot23.withColumn("resp_pkts", F.col("resp_pkts").cast(IntegerType()))

S3_BUCKET = "iot23-project"
iot23.write.parquet(f"s3a://{S3_BUCKET}/iot23.parquet", mode="overwrite")

job.commit()

