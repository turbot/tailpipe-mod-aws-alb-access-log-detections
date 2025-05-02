locals {
  aws_alb_access_log_detections_common_tags = {
    category = "Detections"
    plugin   = "aws"
    service  = "AWS/ALB"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  request_http_method as operation,
  request_url as resource,
  elb_status_code as status,
  user_agent as actor,
  client_ip as source_ip,
  tp_id as source_id,
  -- Create new aliases to preserve original row data
  elb_status_code as status_src,
  tp_timestamp as timestamp_src,
  *
  exclude (elb_status_code, tp_timestamp)
  EOQ
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "status",
    "actor",
    "source_ip",
    "source_id",
  ]
} 