"""
Vendor-specific actionable remediation blueprints for AegisSec findings.
"""

from typing import Dict


def get_headers_remediation_code() -> Dict[str, str]:
    """Generates standard hardening headers configuration snippets for multiple servers."""
    return {
        "Nginx": (
            "# Add to your nginx server block or http context\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
            "add_header X-Content-Type-Options \"nosniff\" always;\n"
            "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
            "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
            "server_tokens off;"
        ),
        "Apache (.htaccess / httpd.conf)": (
            "<IfModule mod_headers.c>\n"
            "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
            "    Header always set X-Content-Type-Options \"nosniff\"\n"
            "    Header always set X-Frame-Options \"SAMEORIGIN\"\n"
            "    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
            "    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"\n"
            "    Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n"
            "</IfModule>\n"
            "ServerSignature Off\n"
            "ServerTokens Prod"
        ),
        "Caddy": (
            "yourdomain.com {\n"
            "    header {\n"
            "        Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
            "        X-Content-Type-Options \"nosniff\"\n"
            "        X-Frame-Options \"SAMEORIGIN\"\n"
            "        Referrer-Policy \"strict-origin-when-cross-origin\"\n"
            "        Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\"\n"
            "        Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n"
            "        -Server\n"
            "    }\n"
            "}"
        ),
        "Express.js (Node.js)": (
            "// Using the helmet middleware\n"
            "const helmet = require('helmet');\n"
            "const app = express();\n\n"
            "app.use(helmet({\n"
            "    contentSecurityPolicy: {\n"
            "        directives: {\n"
            "            defaultSrc: [\"'self'\"],\n"
            "            scriptSrc: [\"'self'\"],\n"
            "            objectSrc: [\"'none'\"],\n"
            "        },\n"
            "    },\n"
            "    hsts: {\n"
            "        maxAge: 31536000,\n"
            "        includeSubDomains: true,\n"
            "        preload: true,\n"
            "    },\n"
            "}));\n"
            "app.disable('x-powered-by');"
        ),
    }


def get_git_block_remediation_code() -> Dict[str, str]:
    """Generates server rules to deny access to sensitive directories like .git or .env."""
    return {
        "Nginx": (
            "# Block hidden files (.git, .env, etc.)\n"
            "location ~ /\\.(?!well-known) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "Apache (.htaccess)": (
            "# Deny access to sensitive dot files and directories\n"
            "<FilesMatch \"^\\.(?!well-known)\">\n"
            "    Order allow,deny\n"
            "    Deny from all\n"
            "</FilesMatch>"
        ),
        "Caddy": (
            "@blocked {\n"
            "    path */.* \n"
            "    not path */.well-known/*\n"
            "}\n"
            "respond @blocked 404"
        ),
    }


def get_cors_remediation_code() -> Dict[str, str]:
    """Generates CORS remediation code."""
    return {
        "Nginx": (
            "# Strict CORS whitelist checking\n"
            "set $cors \"\";\n"
            "if ($http_origin ~* (https?://(trusted1\\.com|trusted2\\.com))) {\n"
            "    set $cors \"true\";\n"
            "}\n"
            "if ($cors = \"true\") {\n"
            "    add_header 'Access-Control-Allow-Origin' \"$http_origin\" always;\n"
            "    add_header 'Access-Control-Allow-Credentials' 'true' always;\n"
            "}"
        ),
        "Express.js": (
            "const cors = require('cors');\n"
            "const whitelist = ['https://trusted.com', 'https://app.trusted.com'];\n"
            "app.use(cors({\n"
            "    origin: function (origin, callback) {\n"
            "        if (!origin || whitelist.indexOf(origin) !== -1) {\n"
            "            callback(null, true);\n"
            "        } else {\n"
            "            callback(new Error('Blocked by CORS policy'));\n"
            "        }\n"
            "    },\n"
            "    credentials: true\n"
            "}));"
        ),
    }
