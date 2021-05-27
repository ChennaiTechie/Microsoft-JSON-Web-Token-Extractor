# Microsoft JSON Web Token Extractor

I have created a small C# project to extract JSON Web Tokens from memory without dumping anything on disk to avoid detection by Endpoint Detection and Response.

For more information about extracting JSON Web Tokens, please check my blog post:
https://thalpius.com/2021/05/27/microsoft-json-web-token-extractor/

**Note**: I started this project for educational purposes only and I am not by far a programmer so do not expect clean code.

# Usage Microsoft JSON Web Token Extractor

Search for JSON Web Tokens in memory for the PowerShell process:  
```Batchfile
MicrosoftJSONWebTokenExtractor.exe /process:powershell
```

# Screenshots

Getting JSON Web Tokens from PowerShell:  

![Alt text](/Screenshots/MicrosoftJSONWebTokenExtractor01.jpg?raw=true "Getting JSON Web Tokens from PowerShell memory")
