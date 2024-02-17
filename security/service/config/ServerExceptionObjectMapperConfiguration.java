package security.service.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import transfer.contract.exception.ServerException;

@Component
@RequiredArgsConstructor
public class ServerExceptionObjectMapperConfiguration {
    /**
     * Класс для корректного маппинга ServerException в JSON.
     */
    private final ServerExceptionSerializer serverExceptionSerializer;

    /**
     * Бин ObjectMapper для перевода ServerException в JSON.
     *
     * @return бин ObjectMapper
     */
    @Bean(name = "serverExceptionObjectMapper")
    public ObjectMapper serverExceptionObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        module.addSerializer(ServerException.class, serverExceptionSerializer);
        objectMapper.registerModule(module);
        objectMapper.registerModule(new JavaTimeModule());
        return objectMapper;
    }
}
