package web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import web.model.User;
import web.service.UserService;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping(value = "hello")
    public String printWelcome(ModelMap model) {
        List<String> messages = new ArrayList<>();
        messages.add("Hello!");
        messages.add("I'm Spring MVC-SECURITY application");
        messages.add("5.2.0 version by sep'19 ");
        model.addAttribute("messages", messages);
        return "hello";
    }

    @RequestMapping(value = "login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("admin/users")
    public String getTableUsers(@ModelAttribute("user") User user, Model model) {
        List<User> users = userService.getAllUsers();
        model.addAttribute("users", users);
        return "users";
    }

    @GetMapping("user")
    public String infoUser(Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("user", user);
        return "infoUser";
    }

    @GetMapping("admin")
    public String infoAdmin(Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("user", user);
        return "infoAdmin";
    }

    @GetMapping("admin/update")
    public String update(@RequestParam("id") Long id, Model model) {
        User user = userService.getUser(id);
        model.addAttribute("user", user);
        return "update";
    }

    @PostMapping("admin/update/{id}")
    public String updateUser(@ModelAttribute("user") User user, @PathVariable("id") Long id) {
        userService.updateUser(id, user);
        return "redirect:/admin/users";
    }

    @PostMapping("admin/add")
    public String addUser(@ModelAttribute("user") User user, @RequestParam(value = "role", required = false) String role) {
        userService.addUser(user, role);
        return "redirect:/admin/users";
    }

    @GetMapping("admin/delete")
    public String delete(@RequestParam("id") Long id, Model model) {
        model.addAttribute("id", id);
        return "delete";
    }

    @PostMapping("admin/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
        return "redirect:/admin/users";
    }
}