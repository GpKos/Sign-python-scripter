В этой статье я хотел бы описать механизм безопасности API-запросов, с которым я столкнулся в одном из своих проектов. Этот механизм использует ключи RSA для проверки целостности запросов.

Описание проблемы
В рассматриваемом программном обеспечении реализован механизм безопасности, который обеспечивает целостность передаваемого сообщения с помощью подписи RSA. Формируется новый заголовок XX-Signature, который вставляется в запрос.

Приватный ключ - хранится в секрете у клиента и используется для создания цифровой подписи каждого отправляемого API-запроса. Публичный ключ клиента передается серверу, который использует его для верификации подписи запросов. Это гарантирует, что запрос был отправлен именно этим клиентом и не был изменен в процессе передачи.

Ключ для проверки - сервер подписывает уведомления своим приватным ключом, а торговец проверяет их публичным ключом. Все уведомления, отправляемые клиенту, подписываются приватным ключом сервера. Клиент, в свою очередь, используя публичный ключ сервера, проверяет подлинность полученных уведомлений. Это предотвращает подделку уведомлений и гарантирует их целостность.

Формирование подписи
Формирование подписи
Реализованный механизм призван помешать злоумышленникам манипулировать запросами и дальнейшей эксплуатацией. В то же время применяемые меры безопасности затрудняют проведение тестирования на проникновение.

Технические детали
Для тестирования безопасности API и проверки целостности запросов, первоначальной задачей было создание Python-скрипта. Такой подход позволил бы автоматизировать процесс генерации запросов и подписей. Однако, возникла проблема с интеграцией этих запросов в HTTP-запросы для последующей обработки в Burp Suite. Сгенерированный скриптом ключ успешно проходил проверку в терминале, но при вставке ключа в запрос Burp, сервер возвращал ошибку 401 “Signature mismatch”. Это указывало на несоответствие подписи, возможно, вызванное различиями в форматировании запроса, такими как наличие пробелов или различия в представлении данных (raw vs. pretty view в Burp).

Сравнение ответов сервера используя одинаковый ключ
Сравнение ответов сервера используя одинаковый ключ
В качестве альтернативы рассматривалась интеграция скрипта в плагин Burp Suite. В конечном итоге, выбор пал на плагин Python Scripter (ссылки оставил под статьей).  К сожалению, трудности на этом не закончились. Реализовать скрипт внутри Python Scripter не удалось из-за несовместимости: Jython 2.7, используемый в плагине, не поддерживает библиотеку cryptography, необходимую для создания цифровой подписи RSA в исходном скрипте. Это вынудило искать другое решение для реализации проверки целостности запросов.

Решение проблемы


Burp Suite работает с Jython. Jython - это реализация языка Python, которая работает на платформе Java Virtual Machine (JVM). Поскольку Jython взаимодействует с Java-кодом и использует Java-библиотеки, нужно использовать системные вызовы через библиотеку subprocess:

import subprocess

process = subprocess.Popen("<cmd>",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    shell=True)

output, err = process.communicate()

if err.decode() != "":
    raise Exception(err)
Это позволит нам выполнять любую команду в системе с помощью языка Python. На этом этапе у нас есть все необходимые элементы. Далее с помощью AI пишем новый скрипт.

Иллюстрация работы плагина и скрипта
Ниже представлен код Python, реализующий описанный механизм подписи запроса:

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

На рисунке 1 проиллюстрирована попытка отправки запроса без дополнительного заголовка. Как можно заметить, сервер указал на его отсутствие и не обработал сообщение.

Рис. 1. Отправленный запрос и полученный ответ, в котором отсутствуют необходимый дополнительный заголовок безопасности.    
Рис. 1. Отправленный запрос и полученный ответ, в котором отсутствуют необходимый дополнительный заголовок безопасности.    
На рисунке 2 изображена еще одна попытка отправить запрос, на этот раз с добавлением требуемого заголовка. Однако изменение в теле сообщения вызвало отсутствие совместимости с подписью, в результате чего сервер также отклонил сообщение.

Рис. 2. Отправленный запрос и полученный ответ, сообщение подписано неправильно.
Рис. 2. Отправленный запрос и полученный ответ, сообщение подписано неправильно.
На рисунке 3  представлен измененный запрос, зарегистрированный модулем Burp Logger, который был отправлен на сервер.

Рис. 3. Отправленный запрос и полученное сообщение, зарегистрированные в модуле Logger.    
Рис. 3. Отправленный запрос и полученное сообщение, зарегистрированные в модуле Logger.    
Заключение
Механизм использования одноразовых и подписных запросов может быть эффективным способом защиты запросов API от подделки. Без дополнительной информации, предоставленной автором приложения, было бы сложно определить, как построена реализованная цифровая подпись. Представленный мной фрагмент кода значительно облегчает дальнейшее тестирование API, поскольку нет необходимости фокусироваться на обеспечении корректности всех значений заголовков.

подробнее о плагине

примеры использования
