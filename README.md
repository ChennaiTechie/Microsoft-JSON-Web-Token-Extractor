# Microsoft JSON Web Token Extractor

I have created a small C# project to extract JSON Web Tokens from memory without dumping anything on disk to avoid detection by Endpoint Detection and Response. For more information about this attack, see the links below.

**Note**: I started the project for educational purposes only and I am by far not a programmer so do not expect clean code.

For more information about Azure AD SSO, please check my blog post:  
https://thalpius.com <- Direct link coming soon!

# Usage Microsoft JSON Web Token Extractor

Search for JSON Web Tokens in PowerShell process:  
```Batchfile
MicrosoftJSONWebTokenExtractor.exe /process:powershell
```

# Screenshots

Getting JSON Web Tokens from PowerShell:  

![Alt text](/Screenshots/MicrosoftJSONWebTokenExtractor01.jpg?raw=true "Getting JSON Web Tokens from PowerShell memory")
