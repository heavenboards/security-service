package security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import transfer.contract.api.UserApi;

/**
 * Класс для получения данных о пользователях.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    /**
     * Api-клиент для сервиса пользователей.
     */
    private final UserApi userApi;

    /**
     * Получить данные о пользователе по его username.
     *
     * @param username - username
     * @return данные о пользователе
     */
    @Override
    public UserDetails loadUserByUsername(String username) {
        return userApi.findUserByUsername(username);
    }
}
