# Short web application token (Java implement)
The "SWA" token is similar to JWT token but it just shorter.

<img width="1083" alt="image" src="https://user-images.githubusercontent.com/41188285/164160359-cbdb789d-2f31-497e-95e6-83385a772c83.png">


## Install
Gradle example:
```gradle
allprojects {
    repositories {
        mavenCentral()
        maven { url "https://jitpack.io" }
    }
}
dependencies {
    implementation 'com.github.alexzvn:swa-token-java:main-SNAPSHOT'
}
```

Maven example:
```xml
<repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
</repository>

<dependency>
    <groupId>com.github.alexzvn.swa-token-java</groupId>
    <artifactId>swa-token-java</artifactId>
    <version>main-SNAPSHOT</version>
</dependency>

```
## How to use

1. Create SWAT instance

```java
import com.alexzvn.swat.SWAToken;

SWAToken swat = new SWAToken("Your secret");
```

2. Issue new token

```java
String issuer = "user";
String id = "1";
Long ttl = 3600; // seconds

swat.create(issuer, id, ttl);
```

3. Verify a token

```java
swat.verify("token")
```

4. Get token info

```java
import com.alexzvn.swat.token.Token;
import com.alexzvn.swat.token.SignedToken;

try {
    Token token = Token.parse("token");
    
    if (token instanceof SignedToken signedToken) {
        System.out.println("Token: " + signedToken.toString());
    }
        }
} catch (Token.InvalidTokenFormatException e) {
    // token it not follow schema
}
```

5. Change to difference signature provider

```java
// By default SWAT use HS256 to create signature
// Bellow is example to change HS512 algo
swat.use("HS512")
```

6. Custom signature provider

```java
import dev.alexzvn.swat.signature.SignatureProvider;

class CustomSignatureProvider extends SignatureProvider {
    public CustomSignatureProvider(String secret) {
        super(secret);
    }
    
    public String sign(String payload) {
        // your code here
    }
    
    public boolean verify(String payload, String signature) {
        // your code here
    }
}
```

Register to SWAT instance
```java
swat.use("CUSTOM", new CustomSignature("your secret"));
```