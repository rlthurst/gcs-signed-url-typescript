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
  async ({ action, httpMethod, destBucketName, destFileName, destFileType, expires=60 }) => {
    /** https://cloud.google.com/storage/docs/access-control/signing-urls-manually */
    destFileName = encodeURIComponent(destFileName)
    const HOSTNAME = 'https://storage.googleapis.com'
    const PATH_TO_RESOURCE = '/' + destBucketName + "/" + destFileName
    const CREDENTIAL_SCOPE = DateTime.utc().toISODate({format: 'basic'}) + '/auto/storage/goog4_request'
    const DATETIME_ISO_BASIC = DateTime.utc().startOf('second').toISO({suppressMilliseconds: true, format: 'basic'})

    const CANONICAL_HEADERS = action === "write" ? 'content-type:' + destFileType + '\nhost:storage.googleapis.com\n' : 'host:storage.googleapis.com\n'
    const SIGNED_HEADERS =  action === "write" ? 'content-type;host' : 'host'

    const CANONICAL_QUERY_STRING = ['X-Goog-Algorithm=GOOG4-RSA-SHA256',
                                    'X-Goog-Credential=' + encodeURIComponent(process.env.GCS_CLIENT_EMAIL + '/' + CREDENTIAL_SCOPE),
                                    'X-Goog-Date=' + DATETIME_ISO_BASIC,
                                    'X-Goog-Expires=' + expires,
                                    'X-Goog-SignedHeaders=' + encodeURIComponent(SIGNED_HEADERS),
                                   ].join('&')

    const CANONICAL_REQUEST = [httpMethod, PATH_TO_RESOURCE, CANONICAL_QUERY_STRING, CANONICAL_HEADERS, SIGNED_HEADERS, 'UNSIGNED-PAYLOAD'].join('\n')
    const HASHED_CANONICAL_REQUEST =  crypto.createHash('sha256').update(CANONICAL_REQUEST).digest('hex')

    const STRING_TO_SIGN = ['GOOG4-RSA-SHA256', DATETIME_ISO_BASIC, CREDENTIAL_SCOPE, HASHED_CANONICAL_REQUEST].join('\n')
    const REQUEST_SIGNATURE =  crypto.createSign('RSA-SHA256').update(STRING_TO_SIGN).sign(process.env.GCS_PRIVATE_KEY as string, 'hex')

    const url = HOSTNAME + PATH_TO_RESOURCE + '?' + CANONICAL_QUERY_STRING + '&X-Goog-Signature=' + REQUEST_SIGNATURE
    return url
  }
)
