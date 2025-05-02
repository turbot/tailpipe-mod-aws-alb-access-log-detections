locals {
  local_file_inclusion_common_tags = merge(local.aws_alb_access_log_detections_common_tags, {
    category    = "Security"
    attack_type = "Local File Inclusion"
  })
}

benchmark "local_file_inclusion_detections" {
  title       = "Local File Inclusion (LFI) Detections"
  description = "This benchmark contains LFI focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.encoded_path_traversal,
    detection.header_based_local_file_inclusion,
    detection.hidden_file_access,
    detection.os_file_access,
    detection.path_traversal,
    detection.restricted_file_access,
  ]

  tags = merge(local.local_file_inclusion_common_tags, {
    type = "Benchmark"
  })
}

detection "path_traversal" {
  title           = "Path Traversal"
  description     = "Detect directory traversal attacks using path sequences like '../' that attempt to access files outside the intended directory."
  documentation   = file("./detections/docs/path_traversal.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.path_traversal

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "path_traversal" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      request_url is not null
      and (
        -- Directory traversal sequences
        request_url ilike '%../%'
        or request_url ilike '%..\\%'
        or request_url ilike '%/./%'
        or request_url ilike '%\\.\\%'
        or request_url ilike '%/.%'
        or request_url ilike '%\\\\%'
        -- Most common exploits
        or request_url ilike '%../..%'
        or request_url ilike '%../../../%'
        or request_url ilike '%../../../../%'
        or request_url ilike '%..//%'
        or request_url ilike '%../../../../../../../../%'
        -- Bypass techniques
        or request_url ilike '%..;/%'
        or request_url ilike '%..///%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "encoded_path_traversal" {
  title           = "Encoded Path Traversal"
  description     = "Detect directory traversal attacks using URL encoded or otherwise obfuscated path sequences to bypass security filters."
  documentation   = file("./detections/docs/encoded_path_traversal.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.encoded_path_traversal

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "encoded_path_traversal" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      request_url is not null
      and (
        -- URL encoded traversal sequences
        request_url ilike '%..%2f%'
        or request_url ilike '%..%2F%'
        or request_url ilike '%..%5c%'
        or request_url ilike '%..%5C%'
        or request_url ilike '%%2e%2e%2f%'
        or request_url ilike '%2e%2e/%'
        or request_url ilike '%2e%2e%2f%'
        or request_url ilike '%2e%2e%5c%'
        -- Double URL encoding
        or request_url ilike '%%252e%252e%252f%'
        or request_url ilike '%%252e%252e%255c%'
        -- Unicode/UTF-8 encoding
        or request_url ilike '%..%c0%af%'
        or request_url ilike '%..%e0%80%af%'
        or request_url ilike '%..%c1%1c%'
        or request_url ilike '%..%c1%9c%'
        -- Overlong UTF-8 encoding
        or request_url ilike '%..%c0%2f%'
        or request_url ilike '%..%c0%5c%'
        or request_url ilike '%..%c0%80%af%'
        -- Hex-encoded
        or request_url ilike '%2e2e2f%'
        or request_url ilike '%2e2e5c%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "os_file_access" {
  title           = "OS File Access"
  description     = "Detect attempts to access sensitive operating system files that might reveal confidential system information."
  documentation   = file("./detections/docs/os_file_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.os_file_access

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "os_file_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      request_url is not null
      and (
        -- Unix/Linux sensitive files
        request_url ilike '%/etc/passwd%'
        or request_url ilike '%/etc/shadow%'
        or request_url ilike '%/etc/hosts%'
        or request_url ilike '%/etc/fstab%'
        or request_url ilike '%/etc/issue%'
        or request_url ilike '%/etc/profile%'
        or request_url ilike '%/etc/ssh%'
        or request_url ilike '%/proc/version%'
        or request_url ilike '%/proc/self%'
        or request_url ilike '%/proc/cpuinfo%'
        or request_url ilike '%/var/log/auth.log%'
        or request_url ilike '%/var/log/secure%'
        -- Windows sensitive files
        or request_url ilike '%c:\\windows\\win.ini%'
        or request_url ilike '%c:\\boot.ini%'
        or request_url ilike '%c:\\windows\\system32\\config%'
        or request_url ilike '%c:\\windows\\repair%'
        or request_url ilike '%c:\\windows\\debug\\netsetup.log%'
        or request_url ilike '%c:\\windows\\iis%log%'
        or request_url ilike '%c:\\sysprep.inf%'
        or request_url ilike '%c:\\sysprep\\sysprep.xml%'
        -- Web server files
        or request_url ilike '%/var/log/apache%'
        or request_url ilike '%/var/log/httpd%'
        or request_url ilike '%/usr/local/apache%'
        or request_url ilike '%/usr/local/nginx%'
        or request_url ilike '%/var/log/nginx%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "restricted_file_access" {
  title           = "Restricted File Access"
  description     = "Detect attempts to access restricted application files, such as configuration files, that might reveal sensitive application data."
  documentation   = file("./detections/docs/restricted_file_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.restricted_file_access

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "restricted_file_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      request_url is not null
      and (
        -- Common application config files
        request_url ilike '%/config.php%'
        or request_url ilike '%/configuration.php%'
        or request_url ilike '%/db.php%'
        or request_url ilike '%/database.php%'
        or request_url ilike '%/settings.php%'
        or request_url ilike '%/conf.php%'
        or request_url ilike '%/wp-config.php%'
        or request_url ilike '%/config.xml%'
        or request_url ilike '%/app.config%'
        or request_url ilike '%/appsettings.json%'
        or request_url ilike '%/config.yml%'
        or request_url ilike '%/config.yaml%'
        or request_url ilike '%/.env%'
        or request_url ilike '%/.htaccess%'
        or request_url ilike '%/.svn/%'
        or request_url ilike '%/.git/%'
        -- Popular application source files
        or request_url ilike '%/web.config%'
        or request_url ilike '%/php.ini%'
        or request_url ilike '%/.htpasswd%'
        or request_url ilike '%.inc%'
        -- Temporary or backup files that may contain sensitive data
        or request_url ilike '%~%'
        or request_url ilike '%.bak%'
        or request_url ilike '%.backup%'
        or request_url ilike '%.old%'
        or request_url ilike '%.orig%'
        or request_url ilike '%.tmp%'
        or request_url ilike '%.temp%'
        or request_url ilike '%.swp%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "hidden_file_access" {
  title           = "Hidden File Access"
  description     = "Detect attempts to access hidden files and directories, which may contain sensitive configuration data or credentials."
  documentation   = file("./detections/docs/hidden_file_access.md")
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.hidden_file_access

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0007:T1083",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "hidden_file_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      request_url is not null
      and (
        -- Common hidden files and directories
        request_url ilike '%/.git/%'
        or request_url ilike '%/.svn/%'
        or request_url ilike '%/.DS_Store%'
        or request_url ilike '%/.htpasswd%'
        or request_url ilike '%/.npmrc%'
        or request_url ilike '%/.env%'
        or request_url ilike '%/.aws/%'
        or request_url ilike '%/.ssh/%'
        or request_url ilike '%/.bash_history%'
        or request_url ilike '%/.htaccess%'
        or request_url ilike '%/.htpasswd%'
        or request_url ilike '%/.config/%'
        or request_url ilike '%/.vscode/%'
        or request_url ilike '%/.idea/%'
        -- Docker/Kubernetes files
        or request_url ilike '%/docker-compose%'
        or request_url ilike '%/Dockerfile%'
        or request_url ilike '%/kubernetes/%'
        or request_url ilike '%/kubeconfig%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "header_based_local_file_inclusion" {
  title           = "Header-Based Local File Inclusion"
  description     = "Detect when a web server received requests with LFI attack patterns in the User-Agent or other headers, which may indicate attempts to bypass basic WAF protections."
  documentation   = file("./detections/docs/header_based_local_file_inclusion.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.header_based_local_file_inclusion

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1190",
    owasp_top_10     = "A01:2021-Broken Access Control"
  })
}

query "header_based_local_file_inclusion" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      user_agent is not null
      and (
        -- Path traversal in User-Agent
        user_agent ilike '%../%'
        or user_agent ilike '%/../%'
        or user_agent ilike '%\\..\\%'
        or user_agent ilike '%\\.\\%'
        -- Encoded path traversal in User-Agent
        or user_agent ilike '%..%2f%'
        or user_agent ilike '%..%2F%'
        or user_agent ilike '%%2e%2e%2f%'
        or user_agent ilike '%%2E%2E%2F%'
        or user_agent ilike '%..%5c%'
        or user_agent ilike '%..%5C%'
        -- OS file access in User-Agent
        or user_agent ilike '%/etc/passwd%'
        or user_agent ilike '%/etc/shadow%'
        or user_agent ilike '%/etc/hosts%'
        or user_agent ilike '%/proc/self/%'
        or user_agent ilike '%win.ini%'
        or user_agent ilike '%system32%'
        or user_agent ilike '%boot.ini%'
      )
    order by
      tp_timestamp desc;
  EOQ
} 