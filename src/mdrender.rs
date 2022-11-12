use std::{path::PathBuf, fs::{read_dir, remove_dir_all}};
use super::*;

use pandoc::{OutputKind, PandocOption};
use std::fs::create_dir;


pub fn md_render(path: PathBuf) {
    const CSS_PATH: &str = "css/main.css";
    
    let css = if path.join(CSS_PATH).is_file() {
        Some(CSS_PATH.into())
    } else { None };

    md_render_internal(path, css);
}


fn md_render_internal(path: PathBuf, css: Option<String>) {
    let dir = unwrap_result_or_default_error!(
        read_dir(path.clone()),
        "listing directory: {path:?}"
    );

    let cache_dir = path.join(".cache");
    if cache_dir.is_dir() {
        unwrap_result_or_default_error!(
            remove_dir_all(cache_dir.clone()),
            "deleting {cache_dir:?}"
        );
    }

    for entry in dir {
        let entry_path = unwrap_result_or_default_error!(
            entry,
            "reading listed entry in {path:?}"
        ).path();

        if entry_path.is_dir() {
            md_render_internal(entry_path, css.clone());
            continue
        }
        
        if !entry_path.extension().contains(&"md") {
            continue
        }

        if !cache_dir.is_dir() {
            unwrap_result_or_default_error!(
                create_dir(cache_dir.clone()),
                "creating {cache_dir:?}"
            );
        }

        let mut pandoc = pandoc::new();
        pandoc.add_input(&entry_path);

        let mut new_path = entry_path.parent().unwrap().to_path_buf();
        new_path.push(".cache");
        new_path.push(entry_path.file_name().unwrap());
        new_path.set_extension("html");
        
        pandoc.set_output(OutputKind::File(new_path));
        pandoc.add_option(PandocOption::Standalone);

        if let Some(css_path) = css.as_ref() {
            pandoc.add_option(PandocOption::Css(css_path.clone()));
        }

        unwrap_result_or_default_error!(
            pandoc.execute(),
            "rendering {entry_path:?} to html"
        );
    }

}