export function write_to_file(path: string, data: string) {
    var file = new File(path, "w");
    file.write(data);
    file.flush();
    file.close();
}
