import csv
import os


def export_csv(output_dir, filename, rows):
    file_path = os.path.join(output_dir, filename)

    if not rows:
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            f.write("")
        return

    fieldnames = sorted(set().union(*(row.keys() for row in rows)))

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
