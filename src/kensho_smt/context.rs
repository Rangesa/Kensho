//! コンテキスト管理
//!
//! 変数の生成とキャッシュ管理を提供。

use crate::kensho_smt::expr::Expr;
use std::collections::HashMap;

/// SMTコンテキスト
///
/// 変数名の生成と式のキャッシュを管理
pub struct Context {
    /// 一時変数カウンタ
    var_counter: usize,

    /// 式の簡約化キャッシュ
    /// キー: 元の式、値: 簡約化された式
    expr_cache: HashMap<Expr, Expr>,
}

impl Context {
    /// 新しいコンテキストを作成
    pub fn new() -> Self {
        Self {
            var_counter: 0,
            expr_cache: HashMap::new(),
        }
    }

    /// 一意な変数名を生成
    ///
    /// # Arguments
    /// * `prefix` - 変数名のプレフィックス（例: "v", "tmp"）
    ///
    /// # Returns
    /// 生成された一意な変数名（例: "v_0", "tmp_1"）
    pub fn fresh_var_name(&mut self, prefix: &str) -> String {
        let name = format!("{}_{}", prefix, self.var_counter);
        self.var_counter += 1;
        name
    }

    /// 一意な変数を生成
    ///
    /// # Arguments
    /// * `width` - ビット幅
    ///
    /// # Returns
    /// 生成された変数式
    pub fn fresh_var(&mut self, width: u32) -> Expr {
        let name = self.fresh_var_name("v");
        Expr::var(name, width)
    }

    /// キャッシュから簡約化済みの式を取得
    ///
    /// # Arguments
    /// * `expr` - 検索する式
    ///
    /// # Returns
    /// キャッシュに存在する場合はSome(簡約化済みの式)、存在しない場合はNone
    pub fn get_simplified(&self, expr: &Expr) -> Option<&Expr> {
        self.expr_cache.get(expr)
    }

    /// 簡約化した式をキャッシュに追加
    ///
    /// # Arguments
    /// * `original` - 元の式
    /// * `simplified` - 簡約化された式
    pub fn cache_simplified(&mut self, original: Expr, simplified: Expr) {
        self.expr_cache.insert(original, simplified);
    }

    /// キャッシュをクリア
    pub fn clear_cache(&mut self) {
        self.expr_cache.clear();
    }

    /// キャッシュのサイズを取得
    pub fn cache_size(&self) -> usize {
        self.expr_cache.len()
    }

    /// 変数カウンタをリセット
    pub fn reset_var_counter(&mut self) {
        self.var_counter = 0;
    }

    /// コンテキストを完全にリセット
    pub fn reset(&mut self) {
        self.var_counter = 0;
        self.expr_cache.clear();
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_var_name() {
        let mut ctx = Context::new();
        assert_eq!(ctx.fresh_var_name("v"), "v_0");
        assert_eq!(ctx.fresh_var_name("tmp"), "tmp_1");
        assert_eq!(ctx.fresh_var_name("x"), "x_2");
    }

    #[test]
    fn test_fresh_var() {
        let mut ctx = Context::new();
        let var1 = ctx.fresh_var(32);
        let var2 = ctx.fresh_var(64);

        assert_eq!(var1.width(), 32);
        assert_eq!(var2.width(), 64);
        assert!(!var1.is_const());
        assert!(!var2.is_const());
    }

    #[test]
    fn test_cache() {
        let mut ctx = Context::new();
        let original = Expr::add(Expr::const_bv(1, 32), Expr::const_bv(2, 32));
        let simplified = Expr::const_bv(3, 32);

        assert!(ctx.get_simplified(&original).is_none());
        assert_eq!(ctx.cache_size(), 0);

        ctx.cache_simplified(original.clone(), simplified.clone());

        assert_eq!(ctx.cache_size(), 1);
        assert_eq!(ctx.get_simplified(&original), Some(&simplified));
    }

    #[test]
    fn test_reset() {
        let mut ctx = Context::new();
        ctx.fresh_var_name("v");
        ctx.cache_simplified(Expr::const_bv(1, 32), Expr::const_bv(1, 32));

        assert_eq!(ctx.var_counter, 1);
        assert_eq!(ctx.cache_size(), 1);

        ctx.reset();

        assert_eq!(ctx.var_counter, 0);
        assert_eq!(ctx.cache_size(), 0);
    }

    #[test]
    fn test_clear_cache() {
        let mut ctx = Context::new();
        ctx.fresh_var_name("v");
        ctx.cache_simplified(Expr::const_bv(1, 32), Expr::const_bv(1, 32));

        ctx.clear_cache();

        assert_eq!(ctx.var_counter, 1); // カウンタはそのまま
        assert_eq!(ctx.cache_size(), 0); // キャッシュのみクリア
    }
}
