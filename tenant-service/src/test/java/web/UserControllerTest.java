package web;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.futakotome.tenantService.TenantServiceApplication;
import io.futakotome.tenantService.domain.user.core.model.Sex;
import io.futakotome.tenantService.domain.user.core.model.UserSaveCommand;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Transactional
@SpringBootTest(classes = TenantServiceApplication.class)
@RunWith(SpringRunner.class)
public class UserControllerTest {
    private MockMvc mockMvc;
    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    @Rollback(value = false)
    public void testSave() throws Exception {
        UserSaveCommand saveCommand = new UserSaveCommand(
                "admin",
                "admin",
                "zzz",
                "983528987@qq.com",
                "13143536973",
                Sex.MALE,
                25);

        mockMvc.perform(post("/user/")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(saveCommand)))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    public void testGetById() throws Exception {
        mockMvc.perform(get("/user/{id}", "87e3c5ee-a973-48e9-b997-2bdd465db961")
                .contentType("application/json"))
                .andExpect(status().isOk())
                .andDo(print());
    }
}
