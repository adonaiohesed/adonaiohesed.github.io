---
title: File Upload Feature Penetration Test
tags: File-Upload
key: page-file_upload
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

When a file upload feature is present, you should check the following items. Fundamentally, from a developer's perspective, a whitelist or allowlist approach is ideal.

## Checklist

1.  **Check the file extension.**

      * If it is a compressed file, you must also check its contents. Check the target path, level of compression, and the estimated unzip size.
      * Check for double extensions, such as `.jpg.php`.
      * Check if `.php` is executed using null bytes, such as `exploit.jpg%00.php` or `exploit.jpg\00.php`.
      * Only allow extensions that are appropriate for the business logic and choose the least harmful and lowest-risk file types.
      * Allowing SVG files can make the application vulnerable to SSRF, XXE, and XSS attacks.

2.  **Check the file size.** You must verify if it is possible to upload a file larger than the set limit.

      * [Large size file download site](https://testing.taxi/blog/325-giant-file-generator-tool/)

3.  **Check for malicious content detection** using an Eicar test file.

4.  **Verify if the uploaded file path is determined by the client.** The file path should be randomly determined on the server-side.

5.  **Confirm that the Content-Type correctly matches the file extension.**

6.  **Check if any web-executable script files** are among the allowed file extensions, such as `aspx, asp, css, swf, xhtml, rhtml, shtml, jsp, js, pl, php, cgi`. If they are present, attempt related attacks.

7.  **If image uploads are possible,** try to upload a `.php` file containing malicious code by changing its extension to `.jpg`, or upload a malicious file while changing the `Content-Type` to `image/jpeg`.

8.  **Check the file name length limit.** Attempt an attack with a file name longer than 10,000 characters.

9.  **Check if only authorized users can upload files.**

10. **Verify if files are stored on a different server.** At a minimum, it is safer to store them somewhere outside the webroot.

11. **Check if file execution occurs in a sandbox.**

12. **Try to upload a file after changing its name to something like** `"/><svg onload = alert(document.cookie)>`.

## Content-Type

The `Content-Type` header in the HTTP protocol indicates the type of data being transmitted and is defined based on MIME (Multipurpose Internet Mail Extensions) types. The `Content-Type` value helps clients and servers to correctly process and interpret data.

### 1. Text Types

Used for text data, representing human-readable content.

  - `text/plain`: Basic text files (e.g., `.txt`)
  - `text/html`: HTML documents (e.g., `.html`)
  - `text/css`: CSS stylesheets (e.g., `.css`)
  - `text/javascript` or `application/javascript`: JavaScript files (e.g., `.js`)
  - `text/csv`: CSV files (e.g., `.csv`)

### 2. Application Types

Primarily represent binary or special data.

  - `application/json`: JSON data (e.g., API responses)
  - `application/xml`: XML data (e.g., `.xml`)
  - `application/x-www-form-urlencoded`: URL-encoded form data
  - `application/pdf`: PDF documents (e.g., `.pdf`)
  - `application/zip`: ZIP compressed files (e.g., `.zip`)
  - `application/x-httpd-php`: PHP files (e.g., `.php`)
  - `application/octet-stream`: Arbitrary binary data (e.g., file downloads)
  - `application/vnd.ms-excel`: Microsoft Excel files (e.g., `.xls`)
  - `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`: Excel Open XML format (e.g., `.xlsx`)

### 3. Image Types

Represent image data.

  - `image/jpeg`: JPEG images (e.g., `.jpg`, `.jpeg`)
  - `image/png`: PNG images (e.g., `.png`)
  - `image/gif`: GIF images (e.g., `.gif`)
  - `image/svg+xml`: SVG images (e.g., `.svg`)
  - `image/webp`: WebP images (e.g., `.webp`)

### 4. Audio Types

Represent audio data.

  - `audio/mpeg`: MP3 audio files (e.g., `.mp3`)
  - `audio/ogg`: Ogg Vorbis audio files (e.g., `.ogg`)
  - `audio/wav`: WAV audio files (e.g., `.wav`)
  - `audio/flac`: FLAC audio files (e.g., `.flac`)

### 5. Video Types

Represent video data.

  - `video/mp4`: MP4 video files (e.g., `.mp4`)
  - `video/webm`: WebM video files (e.g., `.webm`)
  - `video/ogg`: Ogg video files (e.g., `.ogv`)

### 6. Multipart Types

Used for transmitting composite data.

  - `multipart/form-data`: Form data, including file uploads
  - `multipart/alternative`: Data with various representation formats (e.g., HTML email)
  - `multipart/mixed`: A mix of text and binary data

### 7. Font Types

`Content-Type` for font files used on the web.

  - `font/woff`: WOFF font files (e.g., `.woff`)
  - `font/woff2`: WOFF2 font files (e.g., `.woff2`)
  - `font/ttf`: TrueType font files (e.g., `.ttf`)
  - `font/otf`: OpenType font files (e.g., `.otf`)

### 8. Other Types

`Content-Type` used in specific situations.

  - `application/x-shockwave-flash`: Flash files (e.g., `.swf`)
  - `application/wasm`: WebAssembly files (e.g., `.wasm`)
  - `application/vnd.api+json`: JSON API specification (e.g., REST API responses)

## Security Vulnerabilities Due to Mismatch Between Actual File Content and Content-Type

### 1. File Execution Vulnerability

If a malicious file disguised with a `Content-Type` like `image/png` or `text/plain` is uploaded to the server, the following problems can occur. An attacker can try to upload a desired file by tampering with the `Content-Type` to one that the server allows.

#### Scenario

  - An attacker uploads a file containing PHP code, disguised with the `Content-Type` of `image/jpeg`.
  - The server trusts the `Content-Type`, saves the file, and places it in a directory where files can be executed.
  - As a result, the PHP code uploaded by the attacker can be executed, leading to **Remote Code Execution (RCE)**.

#### Prevention

  - **Verify the actual MIME type of the file**: Use a library like `magic` to check the actual type of the uploaded file.
  - **Configure the upload directory**: Set the upload directory to be non-executable by the web server.

### 2. MIME Sniffing Attack

An attack that exploits a `Content-Type` mismatch to trick the browser into misinterpreting the file's content.

#### Scenario

  - An attacker uploads an `.html` file containing malicious JavaScript, disguised with the `Content-Type` of `text/plain`.
  - When the browser opens the file, it recognizes it as HTML through MIME sniffing.
  - The malicious JavaScript code executes in the browser.

#### Prevention

  - **Set response headers**: Use the `X-Content-Type-Options: nosniff` header to prevent the browser from performing MIME sniffing.
  - **Set Content-Disposition**: Configure `Content-Disposition: attachment` to ensure the file is only handled as a download.

### 3. Evasion of Detection

A malicious file can be uploaded with a forged `Content-Type` to evade detection by certain security solutions (e.g., antivirus, WAF).

#### Scenario

  - An attacker uploads an `.exe` file containing a malicious script, disguised with the `Content-Type` of `image/png`.
  - If the security solution only checks the `Content-Type` and does not analyze the file's content, the file will evade detection.

#### Prevention

  - **Content-based verification**: Analyze the actual content of the file, not just the `Content-Type`.
  - **File signature verification**: Analyze the file header to confirm the file type.

### 4. Denial of Service (DoS) Attack

A `Content-Type` mismatch can lead to excessive use of server resources or abnormal processing.

#### Scenario

  - An attacker uploads large binary data disguised with the `Content-Type` of `application/json`.
  - The server fails while trying to process this data as JSON, leading to a memory leak or CPU overload.

#### Prevention

  - **File size limit**: Restrict the size of uploadable files.
  - **Separate data processing logic**: Add a separate verification step to ensure the `Content-Type` and file content match.

### 5. Client-Side Attack (Stored XSS)

If a malicious file is processed with an incorrect `Content-Type` and delivered to the client, it can lead to a client-side attack.

#### Scenario

  - An attacker uploads an HTML file containing malicious JavaScript while setting the `Content-Type` to `image/png`.
  - The file is treated as a safe image file and served to the client.
  - When the user opens the file, the malicious script executes, resulting in **Stored XSS**.

#### Prevention

  - **File format whitelist**: Clearly restrict the file formats allowed for upload.
  - **Output encoding**: Properly encode the file name or content if it is displayed to the user.

## Vulnerabilities in SVG Files

### Case 1: SSRF

For this exploit, an attacker needs to create an SVG file with the below content and change the controlled server URL to their own server:

```html
<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
<image height="30" width="30" xlink:href="https://controlledserver.com/pic.svg" />
</svg>
```

If they upload this file to the application, there will be a callback if the application is vulnerable.

### Case 2: XXE

Here, attackers create an SVG file with the content shown below, and if the server is vulnerable the content of the local file is visible either in the response or in the image itself.

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### Case 3: Cross-Site Scripting

In this case, attackers need to create an SVG file with the below content. If the server is vulnerable, they will see a pop-up showing that it is.

```html
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert('XSS');</script>
  <rect x="0" height="100" width="100" style="fill: #cccccc"/>
  <line x1="20" y1="80" x2="80" y2="80" style="stroke: #ff0000; stroke-width: 5;"/>
</svg>
```

## How to prevent and mitigate file upload vulnerabilities

  - Your application should always check the content of the uploaded file. If it detects anything malicious, the file must be discarded.
  - Maintain a whitelist of allowed extensions. Make sure that a file does not contain more than one extension.
  - Ensure that the filename does not contain any special characters like “;”, “:”, “\>”, “\<”, “/”, “\\”, “.”, “\*”, “%”, etc.
  - Limit the size of the file name.
  - Limit the size (minimum & maximum) of file uploads to prevent DoS attacks.
  - Make sure to disable execute permissions on the directories where all the uploaded files are stored.
  - Ensure the uploaded files do not replace local files on the server.

  ---

파일 업로드 기능이 있을때에는 다음과 같은 것들을 확인해보면 됩니다. 기본적으로 개발자 입장에서는 white-list or allowlist approach가 이상적입니다.

## Check list
1. 파일 확장자 확인하기.
    - 압축파일일 경우 안의 내용도 확인해야합니다. target path, level of compression, estimated unzip size를 체크해야합니다.
    - .jpg.php 와 같이 double extensions 체크합니다.
    - Null bytes such as exploit.jpg%00.php or exploit.jpg\00.php 와 같이 .php가 실행되는지 체크합니다.
    - 비즈니스 로직에 알맞은 확장자만 허용을 하고 least harmful and lowest risk file type으로 정합니다.
    - svg 파일을 허용할 경우 SSRF, XXE, XXS 공격에 취약할 수 있다.
1. File size check - 한도보다 큰 사이즈의 파일을 올릴 수 있는건 아닌지 확인해야합니다.
    - [Large size file download site](https://testing.taxi/blog/325-giant-file-generator-tool/)
1. Eicar를 이용한 malicious content 기능이 있는지 확인합니다.
1. Upload된 파일 Path가 client에서 정해지는지 확인해야합니다. file path는 server단에서 랜던하게 정해져야합니다.
1. Content-type이 확장자와 제대로 매칭되어 있는지 확인합니다.
1. 허용하는 파일 확장자 중에서 Web executable script files인 aspx, asp, css, swf, xhtml, rhtml, shtml, jsp, js, pl, php, cgi가 있는지 확인합니다. 있으면 관련 공격을 시도해봅니다.
1. Image 업로드가 가능한 경우 악성 코드가 담긴 .php파일을 .jpg로 바꿔서 업로드 하거나 악성파일을 올린채 content-type을 image/jpeg로 바꿔서 공격해봅니다.
1. 파일 이름의 길이제한을 확인합니다. 10000이상의 파일 이름으로 공격을 시도해봅니다.
1. Authorized users만 file upload가 가능한지 체크합니다.
1. File을 다른 서버에 저장한지 안 한지 확인하기. 최소한 webroot 밖에 다른 곳에 저장하는 것이 안전합니다.
1. 파일 실행이 sanbox에서 이루어지는지 체크합니다.
1. 파일 이름을 "/><svg onload = alert(document.cookie)> 와 같이 바꾸어서 업로드해봅니다.

## Content Type
Content-Type 헤더는 HTTP 프로토콜에서 전송되는 데이터의 유형을 나타내며, MIME(Multipurpose Internet Mail Extensions) 타입을 기반으로 정의됩니다. Content-Type 값은 클라이언트와 서버가 데이터를 올바르게 처리하고 해석할 수 있도록 도움을 줍니다.

### 1. **텍스트 타입**
텍스트 데이터에 사용되며, 사람이 읽을 수 있는 콘텐츠를 나타냅니다.

- `text/plain`: 기본 텍스트 파일 (예: `.txt`)
- `text/html`: HTML 문서 (예: `.html`)
- `text/css`: CSS 스타일시트 (예: `.css`)
- `text/javascript` 또는 `application/javascript`: JavaScript 파일 (예: `.js`)
- `text/csv`: CSV 파일 (예: `.csv`)

### 2. **애플리케이션 타입**
주로 바이너리 데이터나 특수 데이터를 나타냅니다.

- `application/json`: JSON 데이터 (예: API 응답)
- `application/xml`: XML 데이터 (예: `.xml`)
- `application/x-www-form-urlencoded`: URL 인코딩된 폼 데이터
- `application/pdf`: PDF 문서 (예: `.pdf`)
- `application/zip`: ZIP 압축 파일 (예: `.zip`)
- `application/x-httpd-php`: PHP 파일 (예: `.php`)
- `application/octet-stream`: 임의의 바이너리 데이터 (예: 파일 다운로드)
- `application/vnd.ms-excel`: Microsoft Excel 파일 (예: `.xls`)
- `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`: Excel Open XML 형식 (예: `.xlsx`)

### 3. **이미지 타입**
이미지 데이터를 나타냅니다.

- `image/jpeg`: JPEG 이미지 (예: `.jpg`, `.jpeg`)
- `image/png`: PNG 이미지 (예: `.png`)
- `image/gif`: GIF 이미지 (예: `.gif`)
- `image/svg+xml`: SVG 이미지 (예: `.svg`)
- `image/webp`: WebP 이미지 (예: `.webp`)

### 4. **오디오 타입**
오디오 데이터를 나타냅니다.

- `audio/mpeg`: MP3 오디오 파일 (예: `.mp3`)
- `audio/ogg`: Ogg Vorbis 오디오 파일 (예: `.ogg`)
- `audio/wav`: WAV 오디오 파일 (예: `.wav`)
- `audio/flac`: FLAC 오디오 파일 (예: `.flac`)

### 5. **비디오 타입**
비디오 데이터를 나타냅니다.

- `video/mp4`: MP4 비디오 파일 (예: `.mp4`)
- `video/webm`: WebM 비디오 파일 (예: `.webm`)
- `video/ogg`: Ogg 비디오 파일 (예: `.ogv`)

### 6. **멀티파트 타입**
복합적인 데이터를 전송하는 데 사용됩니다.

- `multipart/form-data`: 파일 업로드를 포함한 폼 데이터
- `multipart/alternative`: 다양한 표현 형식을 포함한 데이터 (예: HTML 이메일)
- `multipart/mixed`: 텍스트와 바이너리 데이터 혼합

### 7. **폰트 타입**
웹에서 사용하는 폰트 파일에 대한 Content-Type입니다.

- `font/woff`: WOFF 폰트 파일 (예: `.woff`)
- `font/woff2`: WOFF2 폰트 파일 (예: `.woff2`)
- `font/ttf`: TrueType 폰트 파일 (예: `.ttf`)
- `font/otf`: OpenType 폰트 파일 (예: `.otf`)

### 8. **기타 타입**
특정 상황에서 사용되는 Content-Type입니다.

- `application/x-shockwave-flash`: Flash 파일 (예: `.swf`)
- `application/wasm`: WebAssembly 파일 (예: `.wasm`)
- `application/vnd.api+json`: JSON API 스펙 (예: REST API 응답)

## 파일의 실제 내용과 Content-Type 불일치로 인한 보안 취약점

### 1. **파일 실행 취약점**
Content-Type이 `image/png` 또는 `text/plain` 등으로 위장된 악성 파일이 서버에 업로드되면 다음과 같은 문제가 발생할 수 있습니다. 우리가 원하는 파일을 업로드 시키면서 Content-Type을 서버가 허용하는 것으로 변조하여 올리는 시도를 해보는 것이다.

#### 시나리오
- 공격자가 PHP 코드를 포함한 파일을 `image/jpeg`으로 위장하여 업로드.
- 서버가 Content-Type을 신뢰하여 파일을 저장한 후, 해당 파일을 실행 가능한 디렉토리에 배치.
- 결과적으로 공격자가 업로드한 PHP 코드가 실행되어 **원격 코드 실행(RCE)**으로 이어질 수 있음.

#### 방지 방법
- **파일의 실제 MIME 유형 검증**: `magic` 라이브러리 등을 사용하여 업로드된 파일의 실제 유형 확인.
- **업로드 디렉토리 설정**: 업로드 디렉토리를 웹 서버에서 실행 불가능하게 설정.

### 2. **MIME 스니핑(MIME Sniffing) 공격**
Content-Type 불일치를 악용하여 브라우저가 파일 내용을 잘못 해석하도록 유도하는 공격입니다.

#### 시나리오
- 공격자가 악성 JavaScript 코드가 포함된 `.html` 파일을 `text/plain`으로 위장하여 업로드.
- 브라우저가 파일을 열 때 MIME 스니핑으로 HTML로 인식.
- 브라우저에서 악성 JavaScript 코드 실행.

#### 방지 방법
- **응답 헤더 설정**: `X-Content-Type-Options: nosniff` 헤더를 사용하여 브라우저가 MIME 스니핑을 수행하지 않도록 설정.
- **Content-Disposition 설정**: 파일 다운로드로만 처리되도록 `Content-Disposition: attachment`를 설정.

### 3. **파일 탐지 회피**
악성 파일이 특정 보안 솔루션(예: 안티바이러스, WAF)에서 탐지되지 않도록 Content-Type을 위조하여 업로드될 수 있습니다.

#### 시나리오
- 공격자가 악성 스크립트를 포함한 `.exe` 파일을 `image/png`으로 위장하여 업로드.
- 보안 솔루션이 Content-Type만 확인하고 파일 내용을 분석하지 않으면, 해당 파일이 탐지를 우회.

#### 방지 방법
- **내용 기반 검증**: Content-Type뿐 아니라 파일의 실제 내용을 분석.
- **파일 서명 검증**: 파일 헤더를 분석하여 파일 유형을 확인.

### 4. **서비스 거부(DoS) 공격**
Content-Type 불일치로 인해 서버 리소스가 과도하게 사용되거나 비정상적인 처리가 발생할 수 있습니다.

#### 시나리오
- 공격자가 대용량 바이너리 데이터를 `application/json`으로 위장하여 업로드.
- 서버가 해당 데이터를 JSON으로 처리하려다 실패하면서 메모리 누수 또는 CPU 과부하가 발생.

#### 방지 방법
- **파일 크기 제한**: 업로드 가능한 파일 크기를 제한.
- **데이터 처리 로직 분리**: Content-Type과 파일 내용을 일치시키는 별도의 검증 단계 추가.

### 5. **클라이언트 공격 (Stored XSS)**
악성 파일이 잘못된 Content-Type으로 처리되어 클라이언트에 전달되면, 클라이언트 측 공격으로 이어질 수 있습니다.

#### 시나리오
- 공격자가 악성 JavaScript가 포함된 HTML 파일을 업로드하면서 Content-Type을 `image/png`으로 설정.
- 파일이 안전한 이미지 파일로 처리되어 클라이언트에 제공.
- 사용자가 파일을 열 때 악성 스크립트가 실행되어 **Stored XSS** 발생.

#### 방지 방법
- **파일 형식 화이트리스트**: 업로드를 허용하는 파일 형식을 명확히 제한.
- **출력 인코딩**: 파일 이름이나 내용이 사용자에게 노출될 경우 적절히 인코딩.

## SGV 파일의 취약점

### Case 1: SSRF

For this exploit, an attacker needs to create an SVG file with the below content and change the controlled server URL to its own server:
```html
<svg xmlns:svg=”http://www.w3.org/2000/svg" xmlns=”http://www.w3.org/2000/svg" xmlns:xlink=”http://www.w3.org/1999/xlink" width=”200" height=”200">

<image height=”30" width=”30"

xlink:href=”https://controlledserver.com/pic.svg" />

</svg>
```
If they upload this file to the application, there will be a callback if the application is vulnerable.

### Case 2: XXE

Here, attackers create an SVG file with the content shown below, and if the server is vulnerable the content of the local file is visible either in the response or in the image itself.
```html
<?xml version=”1.0" standalone=”yes”?><!DOCTYPE test [ <!ENTITY xxe SYSTEM “file:///etc/hostname” > ]><svg width=”128px” height=”128px” xmlns=”http://www.w3.org/2000/svg" xmlns:xlink=”http://www.w3.org/1999/xlink" version=”1.1"><text font-size=”16" x=”0" y=”16">&xxe;</text></svg>
```

### Case 3: Cross Site Scripting

In this case, attackers need to create an SVG file with the below content. If the server is vulnerable, they will see a pop-up showing that it is.
```html
<svg xmlns=”http://www.w3.org/2000/svg">

<script>alert(‘XSS’);</script>

<rect x=”0" height=”100" width=”100" style=”fill: #cccccc”/>

<line x1=”20" y1=”80" x2=”80" y2=”80" style=”stroke: #ff0000; stroke-width: 5;”/>

</svg>
```

## How to prevent and mitigate file upload vulnerabilities
- Your application should always check the content of the uploaded file. If it detects anything malicious, the file must be discarded.
- Maintain a whitelist of allowed extensions. Make sure that a file does not contain more than one extension.
- Make sure that the filename must not contain any special characters like “;”, “:”, “>”, “<”, “/”, “\”, “.”, “*”, “%” etc.
- Limit the size of the file name.
- Limit the size (minimum & maximum) of file upload to prevent DOS attacks.
- Make sure to disable execute permission on the directories where all the uploaded files are stored.
- Ensure the uploaded files do not replace the local files of the server.