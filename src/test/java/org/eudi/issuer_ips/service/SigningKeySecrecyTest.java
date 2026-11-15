package org.eudi.issuer_ips.service;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * US11, AK 4: private key not in the repo, not in application.properties,
 * not in the log; no HS256 secret left in the credential path.
 */
@ExtendWith(OutputCaptureExtension.class)
class SigningKeySecrecyTest {

    @Test
    void privateKeyNeverAppearsInLogOrOutput(CapturedOutput output) throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        String d = key.getD().toString();

        SigningKeyProvider provider = new SigningKeyProvider(key);
        JwtService jwtService = new JwtService(provider, new IssuerUrlProperties("http://issuer.test"));
        String sdJwt = jwtService.createSdJwt("p1", JwtServiceEs256Test.BUNDLE);

        assertFalse(output.getAll().contains(d), "privater Schlüssel (d) im Log");
        assertFalse(sdJwt.contains(d), "privater Schlüssel (d) im SD-JWT");
        // the startup line shows the public thumbprint only
        assertTrue(output.getAll().contains(provider.thumbprint()));
    }

    @Test
    void publicJwkHasNoPrivatePart() {
        assertFalse(new SigningKeyProvider().publicJwk().isPrivate());
    }

    @Test
    void noHs256SecretOrKeyMaterialInSources() throws IOException {
        List<String> forbidden = List.of("MACSigner", "HS256", "12345678901234567890123456789012",
                "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY");
        assertTrue(findInTree(Path.of("src/main"), forbidden).isEmpty(),
                "Verbotene Inhalte: " + findInTree(Path.of("src/main"), forbidden));
    }

    @Test
    void applicationPropertiesHasNoSigningKey() throws IOException {
        String props = Files.readString(Path.of("src/main/resources/application.properties"));
        assertFalse(props.contains("BEGIN"), "PEM-Block in application.properties");
        assertFalse(props.toLowerCase().contains("signing-key"), "Schlüssel-Property in application.properties");
        assertFalse(props.contains("\"d\""), "JWK mit d in application.properties");
    }

    private static List<String> findInTree(Path root, List<String> forbidden) throws IOException {
        try (Stream<Path> files = Files.walk(root)) {
            return files.filter(Files::isRegularFile)
                    .flatMap(p -> {
                        try {
                            String text = Files.readString(p);
                            return forbidden.stream().filter(text::contains).map(f -> p + ": " + f);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .toList();
        }
    }
}
