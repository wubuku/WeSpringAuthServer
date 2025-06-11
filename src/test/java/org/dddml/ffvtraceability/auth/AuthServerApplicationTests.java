// package org.dddml.ffvtraceability.auth;

// import org.junit.jupiter.api.Test;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.test.web.servlet.MockMvc;

// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// @SpringBootTest
// @AutoConfigureMockMvc
// public class AuthServerApplicationTests {

//     @Autowired
//     private MockMvc mockMvc;

//     @Test
//     public void testLogin() throws Exception {
//         mockMvc.perform(post("/login")
//                 .param("username", "admin")
//                 .param("password", "admin"))
//                 .andExpect(status().is3xxRedirection());
//     }
// }