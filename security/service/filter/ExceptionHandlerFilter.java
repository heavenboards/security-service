package security.service.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import transfer.contract.exception.ApplicationException;
import transfer.contract.exception.BaseErrorCode;

/**
 * Фильтр для обработки исключений, возникающий в фильтрах Spring.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ExceptionHandlerFilter extends OncePerRequestFilter {
    /**
     * Класс для записи ApplicationError в JSON-формат.
     */
    private final ObjectMapper objectMapper;

    /**
     * Метод для обработки исключений.
     *
     * @param request     - запрос
     * @param response    - ответ
     * @param filterChain - цепочка фильтров
     */
    @Override
    @SneakyThrows
    protected void doFilterInternal(final @NonNull HttpServletRequest request,
                                    final @NonNull HttpServletResponse response,
                                    final @NonNull FilterChain filterChain) {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException exception) {
            response.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.getWriter().write(objectMapper
                .writeValueAsString(new ApplicationException(BaseErrorCode.WRONG_JWT_TOKEN,
                    "Got a wrong JWT-token in Authorization header")));
        }
    }
}
