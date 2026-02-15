# URL validation bypass data

Source data from https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet

https://github.com/PortSwigger/url-cheatsheet-data

Slides: https://github.com/PortSwigger/url-cheatsheet-data/tree/main/slides

The tests are broadly divided into:
- SSRF (Server-Side Request Forgery)
- CORS (Cross-Origin Resource Sharing)
- Open Redirection

## Intruder percent encoding

Encodes a payload string by replacing each instance of certain characters by one, two, three, or four escape sequences. These represent the UTF-8 encoding of the character, except Burp Suite Intruder default characters:


[" ",".","/","\\","=","<",">","?","+","&","*",";",":","\"","{","}","|","^","`","#","-"]

## Everything

Percent encodes a payload string by replacing each instance of certain characters by one, two, three, or four escape sequences. These represent the UTF-8 encoding of the character.

## Special chars

Percent encodes a payload string by replacing each instance of certain characters by one, two, three, or four escape sequences. These represent the UTF-8 encoding of the character, except:
["!","$","'","\"","(",")","*",",","-",".","/","\\",":",";","[","]","^","_","{","}","|","~"]

## Unicode escape

Represents a payload string as a six-character sequence \uXXXX, except:
['"','\','\b','\f','\n','\r','\t'] && [0x0020 - 0x007f]

## License notice

The copyright for this data belongs to PortSwigger Web Security.
No license is provided for reuse in derivative cheat sheets.
You may fork the source repo to contribute back upstream.