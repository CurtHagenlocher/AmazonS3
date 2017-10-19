// Use this file to write queries to test your data connector
let
    result = AmazonS3.Contents("https://powerquery.s3-us-west-2.amazonaws.com")
in
    result