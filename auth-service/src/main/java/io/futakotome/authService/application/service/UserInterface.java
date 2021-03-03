package io.futakotome.authService.application.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@FeignClient(name = "tenant-service")
public interface UserInterface {
    @RequestMapping(value = "/v1/users/cert/{username}", method = RequestMethod.GET)
    User getOneUserBy(@PathVariable(name = "username") String username);
}
