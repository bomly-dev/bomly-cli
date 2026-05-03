pub fn answer() -> usize {
    bomly_cargo_smoke_helper::value()
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        bomly_cargo_smoke_dev::assert_value(42);
    }
}
