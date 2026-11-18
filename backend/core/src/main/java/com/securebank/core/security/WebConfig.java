package com.securebank.core.security;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final Path uploadDirectory;
    private final Path webRoot;

    public WebConfig(@Value("${app.upload-dir:static/uploads}") String uploadDir,
                     @Value("${app.web-root:static}") String webRootDir) {
        this.uploadDirectory = Paths.get(uploadDir).toAbsolutePath().normalize();
        this.webRoot = Paths.get(webRootDir).toAbsolutePath().normalize();
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                // VULN: [A07-Lab18] Session Fixation support - credentials are allowed so that
                // the JSESSIONID cookie travels with cross-origin requests during development.
                // FIX:  restrict allowedOrigins to the known frontend origin in production.
                .allowedOriginPatterns("http://localhost:*", "http://127.0.0.1:*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true);
    }

    /**
     * Serves the upload directory and the dot-prefixed web-root files.
     *
     * <p>VULN: [A08-Lab22] Unrestricted File Upload - the uploads directory is mapped
     * as a static resource handler, so any file dropped there by the upload endpoint
     * is served back verbatim with no authentication, no content-type sniffing
     * protection and no download disposition. A .html or .svg file becomes an
     * active payload in the victim's browser; a .jsp file becomes server-side code
     * on a container that interprets it.</p>
     *
     * <p>FIX:  store uploads outside the web root, serve them from a dedicated
     * controller that sets Content-Disposition: attachment and a fixed
     * application/octet-stream content type, and never execute anything from
     * user input.</p>
     *
     * <p>VULN: [A02-Lab6] Sensitive File Exposure - the handler below also maps
     * {@code /.env} and {@code /.git/**}, which Spring Boot's default static
     * resource handling deliberately refuses to serve because of the leading dot.
     * This explicit handler undoes that protection, so the environment file and the
     * repository's git config are downloadable by anyone who guesses the path.</p>
     *
     * <p>FIX:  never ship a .env file or a .git directory inside the document root,
     * and never map dot-prefixed paths as static resources.</p>
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/uploads/**")
                .addResourceLocations(uploadDirectory.toUri().toString());

        // VULN: [A02-Lab6] Sensitive File Exposure - the web root is served straight
        // off the filesystem, so the database dump that the entrypoint writes into
        // it (backup.zip) is downloadable without authentication, as are the .env
        // file and the .git directory.
        // FIX:  serve static assets from a directory that only contains assets, keep
        //        secrets and database dumps out of the document root, and put an
        //        authentication check in front of anything sensitive.
        registry.addResourceHandler("/**")
                .addResourceLocations(webRoot.toUri().toString())
                .addResourceLocations("classpath:/static/");

        registry.addResourceHandler("/.env")
                .addResourceLocations("classpath:/static/");
        registry.addResourceHandler("/.git/**")
                .addResourceLocations(webRoot.resolve(".git").toUri().toString());
    }
}
