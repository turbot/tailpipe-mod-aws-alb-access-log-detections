locals {
  cross_site_scripting_common_tags = merge(local.aws_alb_access_log_detections_common_tags, {
    category = "Cross-Site Scripting"
  })
}

benchmark "cross_site_scripting_detections" {
  title       = "Cross-Site Scripting (XSS) Detections"
  description = "This benchmark contains cross-site scripting (XSS) focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.cross_site_scripting_angular_template,
    detection.cross_site_scripting_attribute_injection,
    detection.cross_site_scripting_common_patterns,
    detection.cross_site_scripting_dom_based,
    detection.cross_site_scripting_encoding,
    detection.cross_site_scripting_html_injection,
    detection.cross_site_scripting_javascript_methods,
    detection.cross_site_scripting_javascript_uri,
    detection.cross_site_scripting_script_tag,
  ]

  tags = merge(local.cross_site_scripting_common_tags, {
    type = "Benchmark"
  })
}

detection "cross_site_scripting_common_patterns" {
  title           = "Cross-Site Scripting Common Patterns"
  description     = "Detect basic Cross-Site Scripting (XSS) attack patterns in HTTP requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_common_patterns.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_common_patterns

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_common_patterns" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- Common XSS patterns
          request_url ilike '%alert(%'
          or request_url ilike '%prompt(%'
          or request_url ilike '%confirm(%'
          or request_url ilike '%eval(%'
          or request_url ilike '%document.cookie%'
          or request_url ilike '%document.domain%'
          or request_url ilike '%document.write%'
          -- URL encoded variants
          or request_url ilike '%&#x3C;script%'
          or request_url ilike '%\\x3Cscript%'
        )
      )
      OR
      (
        user_agent is not null
        and (
          -- Common XSS patterns
          user_agent ilike '%alert(%'
          or user_agent ilike '%prompt(%'
          or user_agent ilike '%confirm(%'
          or user_agent ilike '%eval(%'
          or user_agent ilike '%document.cookie%'
          or user_agent ilike '%document.domain%'
          or user_agent ilike '%document.write%'
          -- URL encoded variants
          or user_agent ilike '%&#x3C;script%'
          or user_agent ilike '%\\x3Cscript%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_script_tag" {
  title           = "Cross-Site Scripting Script Tag"
  description     = "Detect Cross-Site Scripting attacks using script tags to execute arbitrary JavaScript code in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_script_tag.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_script_tag

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_script_tag" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- Standard script tags
          request_url ilike '%<script>%'
          or request_url ilike '%<script%src%'
          or request_url ilike '%<script/%'
          -- Obfuscated script tags
          or request_url ilike '%<scr%ipt%'
          or request_url ilike '%<scr\\x00ipt%'
          or request_url ilike '%<s%00cript%'
        )
      )
      OR
      (
        user_agent is not null
        and (
          -- Standard script tags
          user_agent ilike '%<script>%'
          or user_agent ilike '%<script%src%'
          or user_agent ilike '%<script/%'
          -- Obfuscated script tags
          or user_agent ilike '%<scr%ipt%'
          or user_agent ilike '%<scr\\x00ipt%'
          or user_agent ilike '%<s%00cript%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_attribute_injection" {
  title           = "Cross-Site Scripting Attribute Injection"
  description     = "Detect Cross-Site Scripting attacks using HTML attribute injection, such as event handlers or dangerous attributes in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_attribute_injection.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_attribute_injection

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_attribute_injection" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- Attribute injection patterns
          request_url ilike '%onerror=%'
          or request_url ilike '%onload=%'
          or request_url ilike '%onmouseover=%'
          or request_url ilike '%onmouseout=%'
          or request_url ilike '%onclick=%'
          or request_url ilike '%onfocus=%'
          or request_url ilike '%onblur=%'
          or request_url ilike '%onchange=%'
          or request_url ilike '%onsubmit=%'
          or request_url ilike '%onkeypress=%'
          -- Less common event handlers
          or request_url ilike '%onreadystatechange=%'
          or request_url ilike '%onbeforeonload=%'
          or request_url ilike '%onanimationstart=%'
          -- Dangerous attributes
          or request_url ilike '%formaction=%'
          or request_url ilike '%xlink:href=%'
          or request_url ilike '%data:text/html%'
          or request_url ilike '%pattern=%'
        )
      )
      OR
      (
        user_agent is not null
        and (
          -- Attribute injection patterns
          user_agent ilike '%onerror=%'
          or user_agent ilike '%onload=%'
          or user_agent ilike '%onmouseover=%'
          or user_agent ilike '%onmouseout=%'
          or user_agent ilike '%onclick=%'
          or user_agent ilike '%onfocus=%'
          or user_agent ilike '%onblur=%'
          or user_agent ilike '%onchange=%'
          or user_agent ilike '%onsubmit=%'
          or user_agent ilike '%onkeypress=%'
          -- Less common event handlers
          or user_agent ilike '%onreadystatechange=%'
          or user_agent ilike '%onbeforeonload=%'
          or user_agent ilike '%onanimationstart=%'
          -- Dangerous attributes
          or user_agent ilike '%formaction=%'
          or user_agent ilike '%xlink:href=%'
          or user_agent ilike '%data:text/html%'
          or user_agent ilike '%pattern=%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_javascript_uri" {
  title           = "Cross-Site Scripting JavaScript URI"
  description     = "Detect Cross-Site Scripting attacks using javascript: URI schemes in attributes like href or src in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_javascript_uri.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_javascript_uri

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_javascript_uri" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- JavaScript URI schemes
          request_url ilike '%javascript:%'
          or request_url ilike '%vbscript:%'
          -- Obfuscated javascript: URIs
          or request_url ilike '%jav&#x0A;ascript:%'
          or request_url ilike '%javascript:url(%'
        )
      )
      or
      (
        user_agent is not null
        and (
          -- JavaScript URI schemes
          user_agent ilike '%javascript:%'
          or user_agent ilike '%vbscript:%'
          -- Obfuscated javascript: URIs
          or user_agent ilike '%jav&#x0A;ascript:%'
          or user_agent ilike '%javascript:url(%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_dom_based" {
  title           = "Cross-Site Scripting DOM Based"
  description     = "Detect potential DOM-based Cross-Site Scripting attacks targeting JavaScript DOM manipulation in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_dom_based.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_dom_based

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_dom_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- DOM manipulation methods
          request_url ilike '%document.getElementById%'
          or request_url ilike '%document.querySelector%'
          or request_url ilike '%document.write%'
          or request_url ilike '%innerHTML%'
          or request_url ilike '%outerHTML%'
          or request_url ilike '%document.location%'
          or request_url ilike '%window.location%'
          or request_url ilike '%document.URL%'
          or request_url ilike '%document.documentURI%'
          or request_url ilike '%document.referrer%'
          or request_url ilike '%window.name%'
          or request_url ilike '%location.hash%'
          or request_url ilike '%location.search%'
          or request_url ilike '%location.href%'
        )
      )
      or
      (
        user_agent is not null
        and (
          -- DOM manipulation methods
          user_agent ilike '%document.getElementById%'
          or user_agent ilike '%document.querySelector%'
          or user_agent ilike '%document.write%'
          or user_agent ilike '%innerHTML%'
          or user_agent ilike '%outerHTML%'
          or user_agent ilike '%document.location%'
          or user_agent ilike '%window.location%'
          or user_agent ilike '%document.URL%'
          or user_agent ilike '%document.documentURI%'
          or user_agent ilike '%document.referrer%'
          or user_agent ilike '%window.name%'
          or user_agent ilike '%location.hash%'
          or user_agent ilike '%location.search%'
          or user_agent ilike '%location.href%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_html_injection" {
  title           = "Cross-Site Scripting HTML Injection"
  description     = "Detect Cross-Site Scripting attacks using HTML tag injection that may execute JavaScript in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_html_injection.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_html_injection

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_html_injection" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- Common HTML tags that can be used for XSS
          request_url ilike '%<iframe%src=%'
          or request_url ilike '%<img%src=%' and (
              request_url ilike '%onerror=%' 
              or request_url ilike '%onload=%'
          )
          or request_url ilike '%<svg%on%=' -- SVG with event handlers
          or request_url ilike '%<svg><script%' -- SVG containing script
          or request_url ilike '%<object%data=%' and request_url not ilike '%application/pdf%'
          or request_url ilike '%<embed%src=%' and request_url not ilike '%application/pdf%'
          or request_url ilike '%<video%src=%' and (
              request_url ilike '%onerror=%' 
              or request_url ilike '%onload=%'
          )
          or request_url ilike '%<audio%src=%' and (
              request_url ilike '%onerror=%' 
              or request_url ilike '%onload=%'
          )
        )
      )
      or
      (
        user_agent is not null
        and (
          -- HTML tags with dangerous attributes (reduces false positives)
          user_agent ilike '%<iframe%src=%' 
          or user_agent ilike '%<iframe%srcdoc=%'
          or user_agent ilike '%<img%src=%' and (
              user_agent ilike '%onerror=%' 
              or user_agent ilike '%onload=%'
          )
          or user_agent ilike '%<svg%on%=' -- SVG with event handlers
          or user_agent ilike '%<svg><script%' -- SVG containing script
          or user_agent ilike '%<object%data=%' and user_agent not ilike '%application/pdf%'
          or user_agent ilike '%<embed%src=%' and user_agent not ilike '%application/pdf%'
          or user_agent ilike '%<video%src=%' and (
              user_agent ilike '%onerror=%' 
              or user_agent ilike '%onload=%'
          )
          or user_agent ilike '%<audio%src=%' and (
              user_agent ilike '%onerror=%' 
              or user_agent ilike '%onload=%'
          )
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_javascript_methods" {
  title           = "Cross-Site Scripting JavaScript Methods"
  description     = "Detect Cross-Site Scripting attacks using dangerous JavaScript methods like eval(), setTimeout(), and Function() in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_javascript_methods.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_javascript_methods

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_javascript_methods" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- Dangerous JavaScript methods
          request_url ilike '%eval(%'
          or request_url ilike '%setTimeout(%'
          or request_url ilike '%setInterval(%'
          or request_url ilike '%Function(%'
          or request_url ilike '%fetch(%'
          or request_url ilike '%document.write(%'
          or request_url ilike '%document.cookie%'
        )
      )
      or
      (
        user_agent is not null
        and (
          -- Dangerous JavaScript methods
          user_agent ilike '%eval(%'
          or user_agent ilike '%setTimeout(%'
          or user_agent ilike '%setInterval(%'
          or user_agent ilike '%Function(%'
          or user_agent ilike '%fetch(%'
          or user_agent ilike '%document.write(%'
          or user_agent ilike '%document.cookie%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_encoding" {
  title           = "Cross-Site Scripting Encoding"
  description     = "Detect Cross-Site Scripting attacks using various encoding techniques to bypass filters in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_encoding.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_encoding

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_encoding" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- HTML entity encoding
          request_url ilike '%&#x3C;script%' -- Hex entity encoded <script
          or request_url ilike '%&#60;script%' -- Decimal entity encoded <script
          or request_url ilike '%&#x3c;%&#x2f;script&#x3e;%' -- Hex encoded </script>
          or request_url ilike '%&#x3c;img%&#x6f;nerror%' -- Hex encoded <img and onerror
          -- Base64 encoding
          or request_url ilike '%data:text/html;base64,%'
          -- URL encoding
          or request_url ilike '%\\u00%'
          or request_url ilike '%\\x%'
          -- UTF-7 encoding (IE specific)
          or request_url ilike '%+ADw-%'
        )
      )
      or
      (
        user_agent is not null
        and (
          -- HTML entity encoding
          user_agent ilike '%&#x3C;script%' -- Hex entity encoded <script
          or user_agent ilike '%&#60;script%' -- Decimal entity encoded <script
          or user_agent ilike '%&#x3c;%&#x2f;script&#x3e;%' -- Hex encoded </script>
          or user_agent ilike '%&#x3c;img%&#x6f;nerror%' -- Hex encoded <img and onerror
          -- Base64 encoding
          or user_agent ilike '%data:text/html;base64,%'
          -- URL encoding
          or user_agent ilike '%\\u00%'
          or user_agent ilike '%\\x%'
          -- UTF-7 encoding (IE specific)
          or user_agent ilike '%+ADw-%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cross_site_scripting_angular_template" {
  title           = "Cross-Site Scripting AngularJS Template"
  description     = "Detect potential AngularJS template injection attacks that can lead to Cross-Site Scripting in requests and User-Agent headers."
  documentation   = file("./detections/docs/cross_site_scripting_angular_template.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cross_site_scripting_angular_template

  tags = merge(local.cross_site_scripting_common_tags, {
    mitre_attack_ids = "TA0002:T1059.007",
    owasp_top_10     = "A03:2021-Injection"
  })
}

query "cross_site_scripting_angular_template" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      aws_alb_access_log
    where
      (
        request_url is not null
        and (
          -- Common AngularJS injection patterns
          request_url ilike '%constructor.constructor%'
          or request_url ilike '%$eval%'
          or request_url ilike '%ng-init%'
          or request_url ilike '%ng-bind%'
          or request_url ilike '%ng-include%'
        )
      )
      OR
      (
        user_agent is not null
        and (
          -- Common AngularJS injection patterns
          user_agent ilike '%constructor.constructor%'
          or user_agent ilike '%$eval%'
          or user_agent ilike '%ng-init%'
          or user_agent ilike '%ng-bind%'
          or user_agent ilike '%ng-include%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
} 