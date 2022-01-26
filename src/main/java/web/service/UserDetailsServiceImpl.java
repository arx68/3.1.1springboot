package web.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import web.model.Role;
import web.model.User;
import web.repository.RoleRepository;
import web.repository.UserDao;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserDao userDao;
    private final RoleRepository roleRepository;

    @Autowired
    public UserDetailsServiceImpl(@Autowired UserDao userDao,
                                  @Autowired RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
        this.userDao = userDao;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        UserDetails userDetails =  userDao.loadUserByUsername(s);
        if(userDetails == null)
            throw new UsernameNotFoundException("Oops!");
        return userDetails;
    }

    public void addDefaultUser(String role){
        Role roleDefault = new Role();
        roleDefault.setRole(role);
        Set<Role> roleSet = new HashSet<>();
        roleSet.add(roleDefault);
        User user = new User("admin@mail.ru", "John", "Black", "ADMIN", "111", roleSet);
        if (userDao.loadUserByUsername(user.getLogin()) == null) {
            for (Role temp : user.getRoles()) {
                roleRepository.save(temp);
            }
            userDao.addUser(user);
        }
    }
}
