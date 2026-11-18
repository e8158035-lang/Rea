export interface LogEntry {
  ts: string;
  message: string;
  progress: number;
}

export interface IntegrityCheck {
  filename: string;
  expected_size: number;
  actual_size: number;
  expected_sha256: string;
  actual_sha256: string | null;
  matched: boolean;
}

export interface SplitRecord {
  apk_name: string;
  relative_path?: string;
  role: string;
  file_count: number;
  has_native_libs?: boolean;
  has_resources?: boolean;
}

export interface FrameworkRecord {
  name: string;
  evidence: string[];
  dart_code_analyzed?: boolean;
  status_note?: string;
  assets_count?: number;
}

export interface AppFunctionRecord {
  class_name: string;
  method_name: string;
  evidence: string;
}

export interface ScreenRecord {
  screen_name: string;
  source: string;
  evidence: string;
}

export interface StringRecord {
  value: string;
  evidence: string;
}

export interface PermissionRecord {
  name: string;
  evidence: string;
}

export interface ThirdPartyLibRecord {
  package: string;
  class_count: number;
}

export interface AnalysisResultPayload {
  rea_report: {
    legal_notice: string;
    inputs: Array<{
      filename: string;
      size_bytes: number;
      sha256: string;
      detected_type: {
        primary_type: string;
        sub_type: string;
        magic_hex: string;
        extension_claimed: string;
      };
    }>;
    bundle_manifest_json: Record<string, any> | null;
    splits_processed: SplitRecord[];
    native_libraries_so: Array<{ path: string; abi: string }>;
    frameworks: FrameworkRecord[];
    android_manifest: {
      parsed: boolean;
      package_name: string | null;
      version_code: string | number | null;
      version_name: string | null;
      min_sdk: number | null;
      target_sdk: number | null;
      activities: Array<{ name: string; evidence: string }>;
      services: Array<{ name: string; evidence: string }>;
      receivers: Array<{ name: string; evidence: string }>;
      providers: Array<{ name: string; evidence: string }>;
      permissions: PermissionRecord[];
      error: string | null;
    };
    exe_reports: Array<{
      file: string;
      sub_type: string;
      sections: Array<{ name: string; virtual_address: string; virtual_size: number; raw_size: number; evidence: string }>;
      imports: Array<{ dll: string; functions: string[]; evidence: string }>;
      exports: Array<{ name: string; rva: string; evidence: string }>;
      strings: StringRecord[];
      limitations: string[];
    }>;
    assets_index: Array<{ path: string; size_bytes: number; kind: string }>;
    third_party_libraries: ThirdPartyLibRecord[];
    completeness_report: {
      integrity_verified: boolean;
      integrity_checks: IntegrityCheck[];
      rebuild_classification: string;
      frameworks_detected: FrameworkRecord[];
      tools_status: Record<string, any>;
      warnings: string[];
      summary_counts_app_only: {
        app_classes: number;
        app_functions: number;
        app_screens: number;
        app_strings: number;
        permissions: number;
        native_so_libraries: number;
        third_party_library_packages: number;
        splits_processed: number;
      };
    };
  };
  functions_map: {
    app_functions: AppFunctionRecord[];
    app_classes: Array<{ name: string; evidence: string }>;
    third_party_packages: Record<string, number>;
  };
  screens_index: ScreenRecord[];
  strings_index: StringRecord[];
  permissions: PermissionRecord[];
  completeness_report: any;
  readme_rebuilt: string;
}
