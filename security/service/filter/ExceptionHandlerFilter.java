package security.service.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import transfer.contract.domain.error.ServerErrorCode;
import transfer.contract.exception.ServerException;

/**
 * Фильтр для обработки исключений, возникающий в фильтрах Spring.
 */
@Component
public class ExceptionHandlerFilter extends OncePerRequestFilter {
    /**
     * Бин ObjectMapper для перевода ServerException в JSON.
     */
    private final ObjectMapper objectMapper;

    /**
     * Конструктор с objectMapper.
     *
     * @param objectMapper - objectMapper
     */
    public ExceptionHandlerFilter(
        final @Qualifier("serverExceptionObjectMapper") ObjectMapper objectMapper
    ) {
        this.objectMapper = objectMapper;
    }

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
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write(objectMapper
                .writeValueAsString(ServerException.of(ServerErrorCode.WRONG_JWT_TOKEN,
                    HttpStatus.FORBIDDEN)));
        } catch (Exception exception) {
            response.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.getWriter().write(objectMapper
                .writeValueAsString(ServerException.of(ServerErrorCode.CAUGHT_EXCEPTION,
                    HttpStatus.BAD_REQUEST)));
        }
    }
}
