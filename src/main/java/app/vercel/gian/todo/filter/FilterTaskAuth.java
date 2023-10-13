package app.vercel.gian.todo.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import app.vercel.gian.todo.user.IUserRepository;
import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!request.getServletPath().startsWith("/tasks/")) {
            filterChain.doFilter(request, response);
        } else {
            String authorization = request.getHeader("Authorization");

            if (authorization != null) {
                String authToDecode = authorization.substring("Basic".length()).trim();
                byte[] authDecoded = Base64.getDecoder().decode(authToDecode);

                String authString = new String(authDecoded);

                String[] credentials = authString.split(":");
                String username = credentials[0];
                String password = credentials[1];

                var user = this.userRepository.findByUsername(username);

                if (user != null) {
                    var passVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

                    if (passVerify.verified) {
                        request.setAttribute("idUser", user.getId());
                        filterChain.doFilter(request, response);
                    } else {
                        response.sendError(401);
                    }
                } else {
                    response.sendError(401);
                }
            } else {
                response.sendError(401);

            }
        }

    }

}
