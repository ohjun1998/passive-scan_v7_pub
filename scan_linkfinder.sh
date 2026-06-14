#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1
split -d -n l/20 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

scan_jsluice() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return
    local download_dir="results/${domain}_js_files"

    if [ -d "$download_dir" ] && [ "$(ls -A "$download_dir" 2>/dev/null)" ]; then
        rm -f "results/${domain}_jsluice_raw.txt"
        touch "results/${domain}_jsluice_raw.txt"

        for js_file in "$download_dir"/*.js; do
            [ -f "$js_file" ] || continue
            local fname=$(basename "$js_file")
            jsluice urls "$js_file" 2>/dev/null | jq -r --arg f "$fname" '.url | "\($f)\t\(.)"' >> "results/${domain}_jsluice_raw.txt" || true
        done

        if [ -s "results/${domain}_jsluice_raw.txt" ]; then
            sort -u "results/${domain}_jsluice_raw.txt" > "results/${domain}_linkfinder.txt"
            rm -f "results/${domain}_jsluice_raw.txt"
        else
            echo "" > "results/${domain}_linkfinder.txt"
        fi
    else
        echo "" > "results/${domain}_linkfinder.txt"
    fi
}
export -f scan_jsluice
xargs -P 10 -n 1 -a "$TARGET_FILE" -I {} bash -c 'scan_jsluice "{}"'
rm -f targets_group*
