import { GetSignedUrlConfig } from "@google-cloud/storage"
import { resolver } from "blitz"
import { z } from "zod"
import { setGcsStorage } from "../../core/client"
import { DateTime } from "luxon"
import crypto from 'crypto'

export const GenerateSignedUrl = z.object({
  action: z.enum(["write", "read", "delete", "resumable"]),
  httpMethod: z.enum(["GET", "PUT", "POST"]),
  destBucketName: z.string(),
  destFileName: z.string(),
  destFileType: z.string().optional(),
  expires: z.number().min(60).max(604800).optional()
})

export default resolver.pipe(
  resolver.zod(GenerateSignedUrl),
  resolver.authorize(),
  setGcsStorage,
  async ({ action, httpMethod, destBucketName, destFileName, destFileType, expires=60, gcsStorage }) => {
    /*
    const options: GetSignedUrlConfig = {
      version: 'v4',
      action: action
      expires: Date.now() + expires * 1000
    }
    const [url] = await gcsStorage.bucket(destBucketName).file(destFileName).getSignedUrl(options)
    console.log(url)
    */

    /** https://cloud.google.com/storage/docs/access-control/signing-urls-manually */
    const CREDENTIAL_SCOPE = DateTime.utc().toISODate({format: 'basic'}) + '/auto/storage/goog4_request'
    const DATETIME_ISO_BASIC = DateTime.utc().startOf('second').toISO({suppressMilliseconds: true, format: 'basic'})
    const SIGNED_HEADERS =  action === "write" ? 'content-type;host' : 'host' // make sure this is sorted
    const CANONICAL_QUERY_STRING = ['X-Goog-Algorithm=GOOG4-RSA-SHA256', // If you want to add more query strings, make sure the value is encoded and the query is sorted
                                    'X-Goog-Credential=' + encodeURIComponent(process.env.GCS_CLIENT_EMAIL + '/' + CREDENTIAL_SCOPE),
                                    'X-Goog-Date=' + DATETIME_ISO_BASIC,
                                    'X-Goog-Expires=' + expires,
                                    'X-Goog-SignedHeaders=' + encodeURIComponent(SIGNED_HEADERS),
                                   ].join('&')

    const PATH_TO_RESOURCE = '/' + destBucketName + "/" + destFileName
    const CANONICAL_HEADERS = action === "write" ? 'content-type:' + destFileType + '\nhost:storage.googleapis.com\n' : 'host:storage.googleapis.com\n' // Needs to match signed
    const CANONICAL_REQUEST = [httpMethod, PATH_TO_RESOURCE, CANONICAL_QUERY_STRING, CANONICAL_HEADERS, SIGNED_HEADERS, 'UNSIGNED-PAYLOAD'].join('\n')

    const HASHED_CANONICAL_REQUEST =  crypto.createHash('sha256').update(CANONICAL_REQUEST).digest('hex')
    const STRING_TO_SIGN = ['GOOG4-RSA-SHA256', DATETIME_ISO_BASIC, CREDENTIAL_SCOPE, HASHED_CANONICAL_REQUEST].join('\n')

    const HOSTNAME = 'https://storage.googleapis.com'
    const REQUEST_SIGNATURE =  crypto.createSign('RSA-SHA256').update(STRING_TO_SIGN).sign(process.env.GCS_PRIVATE_KEY as string, 'hex')
    const url = HOSTNAME + PATH_TO_RESOURCE + '?' + CANONICAL_QUERY_STRING + '&X-Goog-Signature=' + REQUEST_SIGNATURE
    return url
  }
)
