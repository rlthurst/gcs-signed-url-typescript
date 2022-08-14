# Manually sign urls for GCS (or S3)

## Signing automatically
```
const gcsStorage = new Storage({
  projectId,
  credentials: {
    client_email,
    private_key,
  },
})
  
const options: GetSignedUrlConfig = {
  version: 'v4',
  action: action
  expires: Date.now() + expires * 1000
}
const [url] = await gcsStorage.bucket(destBucketName).file(destFileName).getSignedUrl(options)
```
For most intents and purposes, the above solution is fine. However, using the google cloud client solution limits us to [60000 signatures per minute](https://cloud.google.com/iam/quotas).

## Signing manually in typescript
```
  async ({ action, httpMethod, destBucketName, destFileName, destFileType, expires=60 }) => {
    const CREDENTIAL_SCOPE = DateTime.utc().toISODate({format: 'basic'}) + '/auto/storage/goog4_request'
    const DATETIME_ISO_BASIC = DateTime.utc().startOf('second').toISO({suppressMilliseconds: true, format: 'basic'})
    const SIGNED_HEADERS =  action === "write" ? 'content-type;host' : 'host' // make sure this is sorted
    
    // If you want to add more query strings, make sure the value is encoded and the query is sorted
    const CANONICAL_QUERY_STRING = ['X-Goog-Algorithm=GOOG4-RSA-SHA256', 
                                    'X-Goog-Credential=' + encodeURIComponent(process.env.GCS_CLIENT_EMAIL + '/' + CREDENTIAL_SCOPE),
                                    'X-Goog-Date=' + DATETIME_ISO_BASIC,
                                    'X-Goog-Expires=' + expires,
                                    'X-Goog-SignedHeaders=' + encodeURIComponent(SIGNED_HEADERS),
                                   ].join('&')

    const PATH_TO_RESOURCE = '/' + destBucketName + "/" + destFileName
    // Needs to match signed
    const CANONICAL_HEADERS = action === "write" ? 'content-type:' + destFileType + '\nhost:storage.googleapis.com\n' : 'host:storage.googleapis.com\n' 
    const CANONICAL_REQUEST = [httpMethod, PATH_TO_RESOURCE, CANONICAL_QUERY_STRING, CANONICAL_HEADERS, SIGNED_HEADERS, 'UNSIGNED-PAYLOAD'].join('\n')

    const HASHED_CANONICAL_REQUEST =  crypto.createHash('sha256').update(CANONICAL_REQUEST).digest('hex')
    const STRING_TO_SIGN = ['GOOG4-RSA-SHA256', DATETIME_ISO_BASIC, CREDENTIAL_SCOPE, HASHED_CANONICAL_REQUEST].join('\n')

    const HOSTNAME = 'https://storage.googleapis.com'
    const REQUEST_SIGNATURE =  crypto.createSign('RSA-SHA256').update(STRING_TO_SIGN).sign(process.env.GCS_PRIVATE_KEY as string, 'hex')
    const url = HOSTNAME + PATH_TO_RESOURCE + '?' + CANONICAL_QUERY_STRING + '&X-Goog-Signature=' + REQUEST_SIGNATURE
    return url
  }
```
### Things to consider:
- We can add more headers and query strings than the ones hard coded above.
- But if we do that it is important that the value of extra query strings are encoded.
- Both query strings and headers are sorted alphabetically before used and hashed
- [For more information](https://cloud.google.com/storage/docs/access-control/signing-urls-manually)
