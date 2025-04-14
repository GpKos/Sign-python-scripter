import base64
import subprocess
try:
    import urllib.parse as urlparse  # Try python 3 first
except ImportError:
    import urllib as urlparse  # Fallback for python 2

PRIVATE_KEY = "/path/to/key"
SIGNATURE_HEADER = 'XX-Signature'

if messageIsRequest:
    print("Executing signature code")

    requestInfo = helpers.analyzeRequest(messageInfo.getRequest())
    headers = requestInfo.getHeaders()
    requestBody = messageInfo.getRequest()[requestInfo.getBodyOffset():]
    url = messageInfo.getUrl()
    method = requestInfo.getMethod().upper()
    path = url.getPath()

    #  Удалено URL-кодирование параметров
    query_string = url.getQuery()
    if query_string:
        path += "?" + query_string

    msg = helpers.bytesToString(requestBody)

    # Construct signature input string with UTF-8 encoding and explicit newline.
    signature_input = "{}\n{}\n{}".format(method, path, msg)

    print('signature_input', signature_input)

    # Use openssl via subprocess.  Correctly handle encoding and decoding.
    try:
        cmd = "openssl dgst -sha256 -sign {}".format(PRIVATE_KEY)  # Use .format() instead of f-string
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = process.communicate(input=signature_input.encode('utf-8'))  # Encode input for openssl

        if err:
            raise Exception(err.decode('utf-8'))

        signature_bytes = base64.b64encode(output).decode('utf-8').strip()  # Base64 encode the result

        signature = signature_bytes
    except Exception as e:
        print("Error creating signature: {}".format(e)) # Use .format() instead of f-string
        signature = ""  # or handle the error in another way, e.g., return None

    new_sign = '{}: {}'.format(SIGNATURE_HEADER, signature)
    print('Adding new', new_sign)

    newHeaders = []
    print("Original headers:", headers)
    # Remove existing XX-Signature headers
    for h in headers:
        if SIGNATURE_HEADER not in h:
            newHeaders.append(h)
        else:
            print('Header exist, removing: ', h)
    print("Headers after removing existing signatures:", newHeaders)

    print("New signature header:", new_sign)

    # Insert the new XX-Signature header as the *second* header in the list.
    if len(newHeaders) > 0:
        newHeaders.insert(1, new_sign)
    else:
        newHeaders.append(new_sign)  # if there are no headers, put as first

    print("Final headers:", newHeaders)
    request = helpers.buildHttpMessage(newHeaders, requestBody)

    messageInfo.setRequest(request)
