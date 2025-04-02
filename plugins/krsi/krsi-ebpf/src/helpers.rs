use aya_ebpf::maps::HashMap;

pub fn try_insert_map_entry<K, V>(map: &HashMap<K, V>, key: &K, value: &V) -> Result<u32, i64> {
    match map.insert(key, value, 0) {
        Ok(()) => Ok(0),
        Err(_) => Err(1),
    }
}

pub fn try_remove_map_entry<K, V>(map: &HashMap<K, V>, key: &K) -> Result<u32, i64> {
    match map.remove(key) {
        Ok(_) => Ok(0),
        Err(_) => Err(1),
    }
}