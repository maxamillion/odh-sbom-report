#!/bin/bash

_OUTPUTDIR="output/"

_BACKGROUND_JOB_PIDS=()

_BACKGROUND_JOB_POOL_SIZE=2

_RHOAI_VERSION="2.14"

###################
# Error handling
_ERRORS=()

fn_log_error() {
    _ERRORS+=("${@}")
}

fn_print_errors() {
    if [[ -n "${_ERRORS[*]}" ]]; then
        printf "\n\nERRORS:\n" >&2
        for error in "${_ERRORS[@]}"; do
            printf "%s\n" "${error}" >&2
        done
    fi
}

fn_debug_out(){
   if [[ -n "${_DEBUG}" ]]; then
      echo "$@" >&2
   fi
}

###################
# Utility functions

fn_mkdir_if_needed() {
   # Ensure the needed dirs exist
    if [[ ! -d "${1}" ]]; then
        mkdir -p "${1}"
    fi
}

###################
# Sanity checks
fn_validate_required_binaries() {
   local missing_binaries=""
   local required_binaries=(
      "syft"
      "curl"
   )

   for binary in "${required_binaries[@]}"; do
      if ! which "${binary}" &> /dev/null; then
         fn_log_error "${FUNCNAME[0]}: ${binary} is required but not installed"
         missing_binaries+=" ${binary}"
      fi
   done

   if [[ -n "${missing_binaries}" ]]; then
      fn_print_errors
      exit
   fi
}

######################
# Run jobs in parallel 
fn_launch_syft_scan_job() {
   local image="${1}"
   local output_file="${2}"

   printf "Scanning %s...\n" "${image}"
   fn_debug_out "DEBUG::${FUNCNAME[0]}: Launching syft scan for image: ${image}"
   fn_debug_out "DEBUG::${FUNCNAME[0]}::COMMAND: syft scan \"${image}\" -q -o json > \"${output_file}\""

   syft scan "${image}" -q -o json > "${output_file}" &
   _BACKGROUND_JOB_PIDS+=($!)
}

###########################
# Wait for jobs to complete
fn_wait_syft_scan_jobs() {
   if [[ "${#_BACKGROUND_JOB_PIDS}" -ge 0 ]]; then
      printf "Waiting for syft scan jobs..."
      for pid in "${_BACKGROUND_JOB_PIDS[@]}"; do
         fn_debug_out "DEBUG::${FUNCNAME[0]}: Waiting for pid: ${pid}"
         printf "."
         wait "${pid}"
      done
   fi
}

fn_wait_for_job_pool_capacity(){
   # Check if there is capacity in the pool
   while [ "$(jobs -r | wc -l)" -ge "${_BACKGROUND_JOB_POOL_SIZE}" ]; do
      sleep 10  # Wait for a job to finish
   done
}


###################
# RHOAI SBOM
fn_rhoai_sbom_generation() {
   # RHOAI version ${1} images
   local rhoai_version="${1}"
   local output_dir="${_OUTPUTDIR}rhoai-${rhoai_version}"
   local raw_image_list=""
   local image_list=()

   if ! [[ -d "${output_dir}" ]]; then
      fn_mkdir_if_needed "${output_dir}"

      raw_image_list="$(
         curl -s https://raw.githubusercontent.com/red-hat-data-services/rhoai-disconnected-install-helper/main/rhoai-${rhoai_version}.md | \
            grep quay.io | sed 's/- name://' | sed 's/- //' | tr -d ' ' | uniq 
         )"
      # Read the output into an array, splitting on newlines
      readarray -t image_list <<< "${raw_image_list}"
      fn_debug_out "DEBUG::${FUNCNAME[0]}::IMAGE_LIST: ${image_list[*]}"

      for image in "${image_list[@]}"; do
         fn_wait_for_job_pool_capacity
         fn_launch_syft_scan_job "${image}" "${output_dir}/${image//\//_}_syft_sbom.json"
      done
   else
      fn_log_error "${FUNCNAME[0]}: SBOM located in ${output_dir} already exists"

   fi
}

#####################
# Generate the report
fn_generate_report() {
   local rhoai_version="${1}"

   local report_file="${_OUTPUTDIR}report.csv"

   local rhoai_output_dir="${_OUTPUTDIR}rhoai-${rhoai_version}"

   local pkg_list=(
      "torch"
      "cuda"
      "vllm"
      "rocm"
   )
   local raw_image_list=""
   local image_name=""

   if ! [[ -f "${report_file}" ]]; then
      printf "Generating report for RHOAI SBOM from image manifests..."

      # Set CSV column headers
      printf "Image,Image Version,Package Name,Package Version,Package Type,Metadata,Source\n" > "${report_file}"

      for json_file in "${rhoai_output_dir}"/*; do
         image_name=$(jq '.source.name' "${json_file}"| tr -d '"')
         image_version=$(jq '.source.version' "${json_file}"| tr -d '"')
         fn_debug_out "DEBUG::${FUNCNAME[0]}::IMAGE_NAME: ${image_name}"
         for pkg in "${pkg_list[@]}"; do
            jq ".artifacts[] | select(.name | contains(\"${pkg}\")) | 
               {in: \"${image_name}\", iv: \"${image_version}\", n: .name, v: .version, t: .type, mds: .metadataType, s: .purl} | 
                  [.[]] | @sh" "${json_file}" | tr ' ' ',' | tr -d '"' | tr -d "'" >> "${report_file}"
         done
      done
      printf " Done!\n"
   else
      fn_log_error "${FUNCNAME[0]}: Report located in ${report_file} already exists"
   fi

}
###################
# main script control flow
fn_main() {
   fn_validate_required_binaries

   fn_debug_out "DEBUG::MAIN::_BACKGROUND_JOB_POOLD: ${_BACKGROUND_JOB_POOL_SIZE}"

   printf "Starting to generate report...\n"

   fn_rhoai_sbom_generation "${_RHOAI_VERSION}"

   fn_wait_syft_scan_jobs
   printf "Done!\n"
   wait #one last wait just to be sure

   fn_generate_report "${_RHOAI_VERSION}"

   # Always print errors
   fn_print_errors
   tput cnorm # fix terminal cursor because of background jobs
}

fn_display_help() {
   printf "%s - Generate report for RHOAI SBOM from image manifests\n" "${0}"
   printf "Usage:\n"
   printf "\t-h Display this help and exit\n"
   printf "\t-p Pool size for background jobs (Default: %s)\n" "${_BACKGROUND_JOB_POOL_SIZE}"
   printf "\t-v Version of RHOAI to generate SBOM for (Default: %s)\n" "${_RHOAI_VERSION}"
   printf "\t-t Temporary directory to store OCI layers during SBOM scan (Default: /tmp/)\n"
}

###################
# parse cli args
while getopts "p:v:h" opt; do
  case $opt in
    p)
      _BACKGROUND_JOB_POOL_SIZE=${OPTARG}
      break
      ;;
    v)
      _RHOAI_VERSION=${OPTARG}
      break
      ;;
    h)
      fn_display_help
      exit 1
      ;;
    \?)
      printf "Invalid option: %s\n" "-${OPTARG}" >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND-1))

# call main function
fn_main

