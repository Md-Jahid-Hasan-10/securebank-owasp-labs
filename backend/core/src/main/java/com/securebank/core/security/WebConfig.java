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
    private final Path assetDirectory;

    public WebConfig(@Value("${app.upload-dir:static/uploads}") String uploadDir,
                     @Value("${app.asset-dir:static/assets}") String assetDir) {
        this.uploadDirectory = Paths.get(uploadDir).toAbsolutePath().normalize();
        this.assetDirectory = Paths.get(assetDir).toAbsolutePath().normalize();
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
     * Serves the upload directory and the static asset directory.
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
     * <p>FIXED: [A02-Lab6] Sensitive File Exposure - this handler used to map
     * {@code /**} at the web root and to map {@code /.env} and {@code /.git/**}
     * explicitly. The former served everything that was dropped into the static
     * tree, and the latter deliberately undid Spring Boot's default protection
     * against dot-prefixed paths. Both mappings are gone; assets are now served
     * from a dedicated directory that contains nothing but assets.</p>
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Lab 22 (A08) - uploaded files are served from their own directory.
        // Unchanged by this fix.
        registry.addResourceHandler("/uploads/**")
                .addResourceLocations(uploadDirectory.toUri().toString());

        // FIXED: [A02-Lab6] Sensitive File Exposure - static assets are now served
        // from a dedicated directory that contains nothing but assets. The previous
        // "/**" handler exposed the entire web root, so /.env, /.git/config and
        // backup.zip were downloadable by anyone without authentication.
        //
        // The explicit "/.env" and "/.git/**" handlers have been removed: Spring
        // Boot's default static resource handling deliberately refuses to serve
        // dot-prefixed paths, and those handlers undid that protection.
        //
        // Nothing is mapped at "/**" any more, so a secret file that is accidentally
        // dropped into the asset directory is no longer reachable by default.
        registry.addResourceHandler("/assets/**")
                .addResourceLocations(assetDirectory.toUri().toString());
    }

}
