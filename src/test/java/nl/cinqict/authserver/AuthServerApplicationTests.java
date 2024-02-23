package nl.cinqict.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureWebTestClient
class AuthServerApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void contextLoads() throws Exception {

//        curl -L -X POST 'http://auth-server:9000/oauth2/device_authorization' -H 'Content-Type: application/x-www-form-urlencoded'
//        -d 'client_id=oidc-client&client_secret=secret'

        MvcResult mvcResult = mockMvc
                .perform(post("/oauth2/device_authorization")
                        .param("client_id", "oidc-client")
                        .param("client_secret", "secret"))
                .andExpect(status().isOk())
                .andReturn();
        System.out.println(mvcResult.getResponse().getContentAsString());

//        String response = webTestClient.post().uri(
//                        x -> x.path("/oauth2/device_authorization")
//                                .queryParam("client_id", "oidc-client")
//                                .queryParam("client_secret", "secret")
//                                .build())
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(String.class)
//                .returnResult()
//                .getResponseBody();
//
//        System.out.println(response);

//        String secret = webTestClient.put()
//                .uri(x -> x.path("/notification_login")
//                        .queryParam(NOTIFICATION_TOKEN, notificationToken)
//                        .build())
//                .exchange()
//                .expectStatus().isOk()
//                .expectBody(String.class)
//                .returnResult().getResponseBody();
//
//        webTestClient.post()
//                .uri(x -> x.path("/login")
//                        .queryParam(USERNAME, "a")
//                        .queryParam(PASSWORD, secret)
//                        .build())
//                .exchange()
//                .expectStatus()
//                .isFound()
    }

}

